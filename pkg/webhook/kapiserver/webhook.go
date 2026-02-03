// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"errors"
	"slices"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/component/extensions/operatingsystemconfig/original/components/kubelet"
	oscutils "github.com/gardener/gardener/pkg/component/extensions/operatingsystemconfig/utils"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/secrets"
)

const (
	// Name is the name of the oidc mutating webhook.
	Name = "oidc"
)

// DefaultAddOptions are the default AddOptions for AddToManager.
var DefaultAddOptions = AddOptions{}

// AddOptions are options to apply when adding the oidc mutating webhook to the manager.
type AddOptions struct {
	// ExtensionClasses contains the extension classes the webhook should handle.
	// Only a single type of extension class is supported at the moment.
	// Depending on the extension class, the webhook will target shoot control plane or garden namespaces.
	ExtensionClasses []extensionsv1alpha1.ExtensionClass
}

// New returns a new mutating webhook that ensures that the kube-apiserver deployment conforms to the oidc-webhook-authenticator requirements.
func New(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger := mgr.GetLogger().WithName("oidc-kapiserver-webhook")
	logger.Info("Adding webhook to manager")

	// We support only a single extension class at a time.
	if len(DefaultAddOptions.ExtensionClasses) > 1 {
		return nil, errors.New("only a single extension class is supported at a time")
	}

	var (
		// The namespace selector is adjusted based on the configured extension class.
		namespaceLabelSelectorRequirement metav1.LabelSelectorRequirement
		secretsManagerIdentity            string
	)
	if len(DefaultAddOptions.ExtensionClasses) == 0 || slices.Contains(DefaultAddOptions.ExtensionClasses, extensionsv1alpha1.ExtensionClassShoot) {
		namespaceLabelSelectorRequirement = metav1.LabelSelectorRequirement{
			Key:      v1beta1constants.LabelExtensionPrefix + "shoot-oidc-service",
			Operator: metav1.LabelSelectorOpIn,
			Values:   []string{"true"},
		}
		secretsManagerIdentity = secrets.ManagerIdentity
	} else if slices.Contains(DefaultAddOptions.ExtensionClasses, extensionsv1alpha1.ExtensionClassGarden) {
		namespaceLabelSelectorRequirement = metav1.LabelSelectorRequirement{
			Key:      corev1.LabelMetadataName,
			Operator: metav1.LabelSelectorOpIn,
			Values:   []string{v1beta1constants.GardenNamespace},
		}
		secretsManagerIdentity = secrets.ManagerIdentityRuntime
	}

	fciCodec := oscutils.NewFileContentInlineCodec()

	mutator := genericmutator.NewMutator(
		mgr,
		NewEnsurer(mgr, logger, secretsManagerIdentity),
		oscutils.NewUnitSerializer(),
		kubelet.NewConfigCodec(fciCodec),
		fciCodec,
		logger,
	)
	types := []extensionswebhook.Type{
		{Obj: &appsv1.Deployment{}},
	}

	handler, err := extensionswebhook.NewBuilder(mgr, logger).WithMutator(mutator, types...).Build()
	if err != nil {
		return nil, err
	}

	webhook := &extensionswebhook.Webhook{
		Name:     Name,
		Provider: "",
		Types:    types,
		Target:   extensionswebhook.TargetSeed,
		Path:     "oidc",
		Webhook: &admission.Webhook{
			Handler: handler,
		},
		NamespaceSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				namespaceLabelSelectorRequirement,
			},
		},
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				v1beta1constants.GardenRole: v1beta1constants.GardenRoleControlPlane,
				v1beta1constants.LabelApp:   v1beta1constants.LabelKubernetes,
				v1beta1constants.LabelRole:  v1beta1constants.LabelAPIServer,
			},
		},
	}

	return webhook, err
}
