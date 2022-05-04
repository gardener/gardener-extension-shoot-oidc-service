// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/secrets"

	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

// NewSecretsManager is an alias for extensionssecretsmanager.SecretsManagerForCluster.
// exposed for testing
var NewSecretsManager = extensionssecretsmanager.SecretsManagerForCluster

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the oidc-webhook-authenticator requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, _ gcontext.GardenContext, new, _ *appsv1.Deployment) error {
	template := &new.Spec.Template
	ps := &template.Spec

	if c := extensionswebhook.ContainerWithName(ps.Containers, v1beta1constants.DeploymentNameKubeAPIServer); c != nil {
		if new.Status.ReadyReplicas <= 0 {
			return nil
		}

		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: constants.WebhookKubeConfigSecretName, Namespace: new.Namespace}}
		if err := e.client.Get(ctx, client.ObjectKeyFromObject(secret), secret); err != nil {
			if apierrors.IsNotFound(err) {
				return nil
			}
			return err
		}

		cluster, err := controller.GetCluster(ctx, e.client, new.Namespace)
		if err != nil {
			return err
		}

		if controller.IsHibernated(cluster) {
			return nil
		}

		configs := secrets.ConfigsFor(new.Namespace)

		secretsManager, err := NewSecretsManager(ctx, e.logger.WithName("secretsmanager"), clock.RealClock{}, e.client, cluster, secrets.ManagerIdentity, configs)
		if err != nil {
			return err
		}

		// Leave the responsibility to generate the CA bundle secret to the lifecycle controller
		caBundleSecret, found := secretsManager.Get(secrets.CAName)
		if !found {
			return nil
		}

		ensureKubeAPIServerIsMutated(ps, c, caBundleSecret.Name)
	}

	return nil
}

// NewEnsurer creates a new oidc mutator.
func NewEnsurer(logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		logger: logger.WithName("oidc-controlplane-ensurer"),
	}
}

// ensureKubeAPIServerIsMutated ensures that the kube-apiserver deployment is mutated accordingly
// so that it is able to communicate with the oidc-webhook-authenticator
func ensureKubeAPIServerIsMutated(ps *corev1.PodSpec, c *corev1.Container, caBundleSecretName string) {
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, oidcWebhookConfigPrefix, constants.AuthenticatorDir+"/kubeconfig")
	c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, oidcWebhookCacheTTLPrefix, "0")

	c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, corev1.VolumeMount{
		Name:      oidcAuthenticatorKubeConfigVolumeName,
		ReadOnly:  true,
		MountPath: constants.AuthenticatorDir,
	})

	c.VolumeMounts = extensionswebhook.EnsureVolumeMountWithName(c.VolumeMounts, corev1.VolumeMount{
		Name:      tokenValidatorSecretVolumeName,
		ReadOnly:  true,
		MountPath: constants.TokenValidatorDir,
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
								{Key: secretutils.DataKeyCertificateBundle, Path: secretutils.DataKeyCertificateBundle},
							},
							LocalObjectReference: corev1.LocalObjectReference{
								Name: caBundleSecretName,
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
