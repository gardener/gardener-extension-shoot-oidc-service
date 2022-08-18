// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/operation/botanist/component/extensions/operatingsystemconfig/original/components/kubelet"
	oscutils "github.com/gardener/gardener/pkg/operation/botanist/component/extensions/operatingsystemconfig/utils"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var logger = log.Log.WithName("oidc-kapiserver-webhook")

// New returns a new mutating webhook that ensures that the kube-apiserver deployment conforms to the oidc-webhook-authenticator requirements.
func New(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Adding webhook to manager")

	fciCodec := oscutils.NewFileContentInlineCodec()

	mutator := genericmutator.NewMutator(
		NewEnsurer(logger),
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

	namespaceSelector := &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{Key: v1beta1constants.LabelExtensionPrefix + "shoot-oidc-service", Operator: metav1.LabelSelectorOpIn, Values: []string{"true"}},
		},
	}

	webhook := &extensionswebhook.Webhook{
		Name:     "oidc",
		Provider: "",
		Types:    types,
		Target:   extensionswebhook.TargetSeed,
		Path:     "oidc",
		Webhook:  &admission.Webhook{Handler: handler},
		Selector: namespaceSelector,
	}

	return webhook, err
}
