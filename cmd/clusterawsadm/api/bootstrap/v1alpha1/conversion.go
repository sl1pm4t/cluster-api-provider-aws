/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	conversion "k8s.io/apimachinery/pkg/conversion"
	"sigs.k8s.io/cluster-api-provider-aws/v2/cmd/clusterawsadm/api/bootstrap/v1beta1"
)

// Convert_v1beta1_AWSIAMConfigurationSpec_To_v1alpha1_AWSIAMConfigurationSpec is an autogenerated conversion function.
func Convert_v1beta1_AWSIAMConfigurationSpec_To_v1alpha1_AWSIAMConfigurationSpec(in *v1beta1.AWSIAMConfigurationSpec, out *AWSIAMConfigurationSpec, s conversion.Scope) error {
	return autoConvert_v1beta1_AWSIAMConfigurationSpec_To_v1alpha1_AWSIAMConfigurationSpec(in, out, s)
}
