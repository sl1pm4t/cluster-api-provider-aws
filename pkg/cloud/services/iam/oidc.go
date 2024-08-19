package iam

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	stderr "errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"k8s.io/utils/ptr"
	"path"
	v1beta13 "sigs.k8s.io/cluster-api/controlplane/kubeadm/api/v1beta1"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"

	iamv1 "sigs.k8s.io/cluster-api-provider-aws/v2/iam/api/v1beta1"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/scope"
	"sigs.k8s.io/cluster-api-provider-aws/v2/pkg/cloud/services/s3"
	clusterv1 "sigs.k8s.io/cluster-api/api/v1beta1"
	v1beta12 "sigs.k8s.io/cluster-api/bootstrap/kubeadm/api/v1beta1"
	"sigs.k8s.io/cluster-api/controllers/remote"
)

const (
	jwksKey                 = "/openid/v1/jwks"
	opendIDConfigurationKey = "/.well-known/openid-configuration"
)

type oidcDiscovery struct {
	Issuer                string   `json:"issuer"`
	JWKSURI               string   `json:"jwks_uri"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	ResponseTypes         []string `json:"response_types_supported"`
	SubjectTypes          []string `json:"subject_types_supported"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported       []string `json:"claims_supported"`
}

func buildDiscoveryJSON(issuerURL string) ([]byte, error) {
	d := oidcDiscovery{
		Issuer:                issuerURL,
		JWKSURI:               fmt.Sprintf("%v/openid/v1/jwks", issuerURL),
		AuthorizationEndpoint: "urn:kubernetes:programmatic_authorization",
		ResponseTypes:         []string{"id_token"},
		SubjectTypes:          []string{"public"},
		SigningAlgs:           []string{"RS256"},
		ClaimsSupported:       []string{"sub", "iss"},
	}
	return json.MarshalIndent(d, "", "")
}

func (s *Service) deleteBucketContents(s3 *s3.Service) error {
	if err := s3.Delete("/" + path.Join(s.scope.Name(), jwksKey)); err != nil {
		return err
	}

	return s3.Delete("/" + path.Join(s.scope.Name(), opendIDConfigurationKey))
}

func (s *Service) buildIssuerURL() string {
	// e.g. s3-us-west-2.amazonaws.com/<bucketname>/<clustername>
	return fmt.Sprintf("https://s3.%s.amazonaws.com/%s/%s", s.scope.Region(), s.scope.Bucket().Name, s.scope.Name())
}

func (s *Service) reconcileBucketContents(ctx context.Context) error {
	clusterKey := client.ObjectKey{
		Name:      s.scope.Name(),
		Namespace: s.scope.Namespace(),
	}

	// get remote config from management cluster
	remoteRestConfig, err := remote.RESTConfig(context.Background(), s.scope.Name(), s.scope.ManagementClient(), clusterKey)
	if err != nil {
		return fmt.Errorf("getting remote rest config for %s/%s: %w", s.scope.Namespace(), s.scope.Name(), err)
	}
	remoteRestConfig.Timeout = scope.DefaultKubeClientTimeout

	// make a client set for the workload cluster
	clientSet, err := kubernetes.NewForConfig(remoteRestConfig)
	if err != nil {
		return err
	}

	// create the OpenID Connect discovery document
	openIDConfig, err := buildDiscoveryJSON(s.buildIssuerURL())
	if err != nil {
		return err
	}

	s3scope := s3.NewService(s.scope)

	if _, err := s3scope.CreatePublic("/"+path.Join(s.scope.Name(), opendIDConfigurationKey), openIDConfig); err != nil {
		return err
	}

	// retrieve Service Account Issuer signing keys from workload cluster API
	jwks, err := get(ctx, clientSet, jwksKey)
	if err != nil {
		return err
	}

	if _, err := s3scope.CreatePublic("/"+path.Join(s.scope.Name(), jwksKey), []byte(jwks)); err != nil {
		return err
	}

	return nil
}

func get(ctx context.Context, clientSet *kubernetes.Clientset, uri string) (ret string, err error) {
	request := clientSet.RESTClient().Get().RequestURI(uri)
	stream, err := request.Stream(ctx)
	if err != nil {
		return
	}
	defer func() {
		err = stream.Close()
	}()

	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(stream)
	if err != nil {
		return
	}

	if err = stream.Close(); err != nil {
		return
	}

	ret = buf.String()
	return
}

func buildOIDCTrustPolicy(arn string) iamv1.PolicyDocument {
	conditionValue := arn[strings.Index(arn, "/")+1:] + ":sub"

	return iamv1.PolicyDocument{
		Version: "2012-10-17",
		Statement: iamv1.Statements{
			iamv1.StatementEntry{
				Sid:    "",
				Effect: "Allow",
				Principal: iamv1.Principals{
					iamv1.PrincipalFederated: iamv1.PrincipalID{arn},
				},
				Action: iamv1.Actions{"sts:AssumeRoleWithWebIdentity"},
				Condition: iamv1.Conditions{
					"ForAnyValue:StringLike": map[string][]string{
						conditionValue: {"system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}"},
					},
				},
			},
		},
	}
}

// FindAndVerifyOIDCProvider will try to find an OIDC provider. It will return an error if the found provider does not
// match the cluster spec.
func findAndVerifyOIDCProvider(issuerURL, thumbprint string, iamClient iamiface.IAMAPI) (string, error) {
	output, err := iamClient.ListOpenIDConnectProviders(&iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return "", errors.Wrap(err, "error listing providers")
	}
	for _, r := range output.OpenIDConnectProviderList {
		provider, err := iamClient.GetOpenIDConnectProvider(&iam.GetOpenIDConnectProviderInput{OpenIDConnectProviderArn: r.Arn})
		if err != nil {
			return "", errors.Wrap(err, "error getting provider")
		}
		// URL should always contain `https`.
		if "https://"+aws.StringValue(provider.Url) != issuerURL {
			continue
		}
		if len(provider.ThumbprintList) != 1 || aws.StringValue(provider.ThumbprintList[0]) != thumbprint {
			return "", errors.Wrap(err, "found provider with matching issuerURL but with non-matching thumbprint")
		}
		if len(provider.ClientIDList) != 1 || aws.StringValue(provider.ClientIDList[0]) != STSAWSAudience {
			return "", errors.Wrap(err, "found provider with matching issuerURL but with non-matching clientID")
		}
		return aws.StringValue(r.Arn), nil
	}
	return "", nil
}

func fetchRootCAThumbprint(url string, port int) (_ string, err error) {
	// Parse cmdline arguments using flag package
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", url, port), &tls.Config{
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return "", err
	}

	defer func() {
		if cerr := conn.Close(); cerr != nil {
			err = stderr.Join(err, cerr)
		}
	}()
	// Get the ConnectionState struct as that's the one which gives us x509.Certificate struct
	cert := conn.ConnectionState().PeerCertificates[0]
	fingerprint := sha1.Sum(cert.Raw) //nolint:gosec // this is not used for real security
	var buf bytes.Buffer
	for _, f := range fingerprint {
		if _, err := fmt.Fprintf(&buf, "%02X", f); err != nil {
			return "", err
		}
	}

	return strings.ToLower(buf.String()), nil
}

// DeleteOIDCProvider will delete an OIDC provider.
func deleteOIDCProvider(arn string, iamClient iamiface.IAMAPI) error {
	if arn == "" {
		return nil
	}

	input := iam.DeleteOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: aws.String(arn),
	}

	_, err := iamClient.DeleteOpenIDConnectProvider(&input)
	if err != nil {

		var aerr awserr.Error
		ok := errors.As(err, &aerr)
		if !ok {
			return errors.Wrap(err, "deleting OIDC provider")
		}

		switch aerr.Code() {
		case iam.ErrCodeNoSuchEntityException:
			return nil
		default:
			return errors.Wrap(err, "deleting OIDC provider")
		}

	}
	return nil
}

// reconcileKubeAPIParameters
// 1. find kubeadmcontrolplane
// 2. use name/namespace to pull kubeadmconfig
// 3. update files/params.
func (s *Service) reconcileKubeAPIParameters(ctx context.Context) error {
	managementClient := s.scope.ManagementClient()
	name := s.scope.Name()
	namespace := s.scope.Namespace()

	s3Host := fmt.Sprintf(S3HostFormat, s.scope.Region())
	accountIssuer := "https://" + path.Join(s3Host, s.scope.Bucket().Name, s.scope.Name())

	listOptions := []client.ListOption{
		client.InNamespace(namespace),
		client.MatchingLabels(map[string]string{clusterv1.ClusterNameLabel: name}),
	}

	controlPlanes := &v1beta13.KubeadmControlPlaneList{}
	if err := managementClient.List(ctx, controlPlanes, listOptions...); err != nil {
		return fmt.Errorf("failed to list kubeadm control planes for cluster %s/%s: %w", namespace, name, err)
	}

	patchContent := `[
		{
			"op": "add",
			"path": "/spec/containers/0/command/1",
			"value": "--api-audiences=https://kubernetes.default.svc.cluster.local"
		},
		{
			"op": "add",
			"path": "/spec/containers/0/command/1",
			"value": "--api-audiences=` + STSAWSAudience + `"
		},
		{
			"op": "add",
			"path": "/spec/containers/0/command/1",
			"value": "--service-account-issuer=` + accountIssuer + `"
		},
		{
			"op": "add",
			"path": "/spec/containers/0/command/1",
			"value": "--service-account-jwks-uri=` + accountIssuer + jwksKey + `"
		}
	]`

	for i := range controlPlanes.Items {
		// files have to be unique so rebuild and toss the ones we're going to add
		var files []v1beta12.File
		for _, file := range controlPlanes.Items[i].Spec.KubeadmConfigSpec.Files {
			if file.Path != "/etc/kubernetes/patches/kube-apiserver0+json.json" {
				files = append(files, file)
			} else if file.Content == patchContent {
				return nil // nothing to reconcile
			}
		}

		controlPlanes.Items[i].Spec.KubeadmConfigSpec.Files = append(files,
			// command starts with 0 == kube-apiserver, json patch add will insert at the position and shift the array
			v1beta12.File{
				Path:    "/etc/kubernetes/patches/kube-apiserver0+json.json",
				Content: patchContent,
			})

		// panic checks to be safe
		if controlPlanes.Items[i].Spec.KubeadmConfigSpec.InitConfiguration == nil {
			controlPlanes.Items[i].Spec.KubeadmConfigSpec.InitConfiguration = &v1beta12.InitConfiguration{
				Patches: &v1beta12.Patches{},
			}
		}

		if controlPlanes.Items[i].Spec.KubeadmConfigSpec.InitConfiguration.Patches == nil {
			controlPlanes.Items[i].Spec.KubeadmConfigSpec.InitConfiguration.Patches = &v1beta12.Patches{}
		}

		// set the patch directory for kubeadmn init to apply before booting apiserver
		controlPlanes.Items[i].Spec.KubeadmConfigSpec.InitConfiguration.Patches.Directory = "/etc/kubernetes/patches"

		if err := managementClient.Update(ctx, &controlPlanes.Items[i]); err != nil {
			return err
		}
	}

	return nil
}

func (s *Service) ownerRef() []metav1.OwnerReference {
	c := s.scope.ClusterObj()
	c.GetObjectKind().GroupVersionKind().GroupVersion().String()
	return []metav1.OwnerReference{
		metav1.OwnerReference{
			APIVersion:         c.GetObjectKind().GroupVersionKind().GroupVersion().String(),
			Kind:               c.GetObjectKind().GroupVersionKind().Kind,
			Name:               s.scope.Name(),
			UID:                c.GetUID(),
			Controller:         ptr.To(true),
			BlockOwnerDeletion: ptr.To(true),
		},
	}
}
