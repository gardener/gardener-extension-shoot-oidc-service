// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"context"
	"strconv"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/secrets"
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

		// we expect that the CA bundle secret is handled by the lifecycle controller
		caBundleSecret, err := getLatestIssuedCABundleSecret(ctx, e.client, new.Namespace)
		if err != nil {
			// if CA secret is still not created we do not want to return an error
			if _, ok := err.(*noCASecretError); ok {
				return nil
			}
			return err
		}

		ensureKubeAPIServerIsMutated(ps, c, caBundleSecret.Name)
	}

	return nil
}

// NewEnsurer creates a new oidc mutator.
func NewEnsurer(mgr manager.Manager, logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		client: mgr.GetClient(),
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
				DefaultMode: ptr.To[int32](420),
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
				},
			},
		},
	})
}

// getLatestIssuedCABundleSecret returns the oidc-webhook latest CA bundle secret
func getLatestIssuedCABundleSecret(ctx context.Context, c client.Client, namespace string) (*corev1.Secret, error) {
	secretList := &corev1.SecretList{}
	if err := c.List(ctx, secretList, client.InNamespace(namespace), client.MatchingLabels{
		secretsmanager.LabelKeyBundleFor:       secrets.CAName,
		secretsmanager.LabelKeyManagedBy:       secretsmanager.LabelValueSecretsManager,
		secretsmanager.LabelKeyManagerIdentity: secrets.ManagerIdentity,
	}); err != nil {
		return nil, err
	}
	return getLatestIssuedSecret(secretList.Items)
}

// getLatestIssuedSecret returns the secret with the "issued-at-time" label that represents the latest point in time
func getLatestIssuedSecret(secrets []corev1.Secret) (*corev1.Secret, error) {
	if len(secrets) == 0 {
		return nil, &noCASecretError{}
	}

	var newestSecret *corev1.Secret
	var currentIssuedAtTime time.Time
	for i := 0; i < len(secrets); i++ {
		// if some of the secrets have no "issued-at-time" label
		// we have a problem since this is the source of truth
		issuedAt, ok := secrets[i].Labels[secretsmanager.LabelKeyIssuedAtTime]
		if !ok {
			return nil, &noIssuedAtTimeError{secretName: secrets[i].Name, namespace: secrets[i].Namespace}
		}

		issuedAtUnix, err := strconv.ParseInt(issuedAt, 10, 64)
		if err != nil {
			return nil, err
		}

		issuedAtTime := time.Unix(issuedAtUnix, 0).UTC()
		if newestSecret == nil || issuedAtTime.After(currentIssuedAtTime) {
			newestSecret = &secrets[i]
			currentIssuedAtTime = issuedAtTime
		}
	}

	return newestSecret, nil
}
