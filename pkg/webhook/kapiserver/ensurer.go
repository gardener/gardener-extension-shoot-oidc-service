// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"k8s.io/apimachinery/pkg/types"
)

const (
	oidcWebhookConfigPrefix               = "--authentication-token-webhook-config-file="
	oidcWebhookCacheTTLPrefix             = "--authentication-token-webhook-cache-ttl="
	oidcAuthenticatorKubeConfigVolumeName = "oidc-webhook-authenticator-kubeconfig"
	tokenValidatorSecretVolumeName        = "token-validator-secret"
)

type ensurer struct {
	genericmutator.NoopEnsurer
	client client.Client
	logger logr.Logger
}

// InjectClient injects the given client into the ensurer.
func (e *ensurer) InjectClient(client client.Client) error {
	e.client = client

	return nil
}

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the oidc-webhook-authenticator requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, _ gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	template := &new.Spec.Template
	ps := &template.Spec

	if c := extensionswebhook.ContainerWithName(ps.Containers, v1beta1constants.DeploymentNameKubeAPIServer); c != nil {
		namespacedName := types.NamespacedName{
			Namespace: new.Namespace,
			Name:      constants.WebhookKubeConfigSecretName,
		}
		secret := &corev1.Secret{}

		if err := e.client.Get(ctx, namespacedName, secret); err != nil {
			if apierrors.IsNotFound(err) {
				ensureKubeAPIServerIsNotMutated(ps, c)
				return nil
			} else {
				return err
			}
		}

		cluster, err := controller.GetCluster(ctx, e.client, new.Namespace)
		if err != nil {
			return err
		}
		if controller.IsHibernated(cluster) {
			ensureKubeAPIServerIsNotMutated(ps, c)
			return nil
		}

		ensureKubeAPIServerIsMutated(ps, c)
	}

	return nil
}

// NewEnsurer creates a new oidc mutator.
func NewEnsurer(logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		logger: logger.WithName("oidc-controlplane-ensurer"),
	}
}

// ensureKubeAPIServerIsNotMutated ensures that any modifications that the webhook
// may have made are not present in the current kube-apiserver deployment
func ensureKubeAPIServerIsNotMutated(ps *corev1.PodSpec, c *corev1.Container) {
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, oidcWebhookConfigPrefix)
	c.Command = extensionswebhook.EnsureNoStringWithPrefix(c.Command, oidcWebhookCacheTTLPrefix)
	c.VolumeMounts = extensionswebhook.EnsureNoVolumeMountWithName(c.VolumeMounts, oidcAuthenticatorKubeConfigVolumeName)
	c.VolumeMounts = extensionswebhook.EnsureNoVolumeMountWithName(c.VolumeMounts, tokenValidatorSecretVolumeName)
	ps.Volumes = extensionswebhook.EnsureNoVolumeWithName(ps.Volumes, oidcAuthenticatorKubeConfigVolumeName)
	ps.Volumes = extensionswebhook.EnsureNoVolumeWithName(ps.Volumes, tokenValidatorSecretVolumeName)
}

// ensureKubeAPIServerIsMutated ensures that the kube-apiserver deployment is mutated accordingly
// so that it is able to communicate with the oidc-webhook-authenticator
func ensureKubeAPIServerIsMutated(ps *corev1.PodSpec, c *corev1.Container) {
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, oidcWebhookConfigPrefix, "/var/run/secrets/oidc-webhook/authenticator/kubeconfig")
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, oidcWebhookCacheTTLPrefix, "0")

	c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, corev1.VolumeMount{
		Name:      oidcAuthenticatorKubeConfigVolumeName,
		ReadOnly:  true,
		MountPath: "/var/run/secrets/oidc-webhook/authenticator",
	})

	c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, corev1.VolumeMount{
		Name:      tokenValidatorSecretVolumeName,
		ReadOnly:  true,
		MountPath: "/var/run/secrets/oidc-webhook/token-validator",
	})

	ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, corev1.Volume{
		Name: oidcAuthenticatorKubeConfigVolumeName,
		VolumeSource: corev1.VolumeSource{
			Secret: &corev1.SecretVolumeSource{
				SecretName: constants.WebhookKubeConfigSecretName,
			},
		},
	})

	ps.Volumes = extensionswebhook.EnsureVolumeWithName(ps.Volumes, corev1.Volume{
		Name: tokenValidatorSecretVolumeName,
		VolumeSource: corev1.VolumeSource{
			Projected: &corev1.ProjectedVolumeSource{
				DefaultMode: pointer.Int32(420),
				Sources: []corev1.VolumeProjection{
					{
						Secret: &corev1.SecretProjection{
							Items: []corev1.KeyToPath{
								{Key: "ca.crt", Path: "ca.crt"},
							},
							LocalObjectReference: corev1.LocalObjectReference{
								Name: v1beta1constants.SecretNameCACluster,
							},
						},
					},
					{
						Secret: &corev1.SecretProjection{
							Items: []corev1.KeyToPath{
								{Key: "token", Path: "token"},
							},
							LocalObjectReference: corev1.LocalObjectReference{
								Name: gutil.SecretNamePrefixShootAccess + constants.ApplicationName + "-token-validator",
							},
						},
					},
				},
			},
		},
	})
}
