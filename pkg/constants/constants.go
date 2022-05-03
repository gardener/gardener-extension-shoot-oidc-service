// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	// ExtensionType is the name of the extension type.
	ExtensionType = "shoot-oidc-service"
	// ServiceName is the name of the service.
	ServiceName = ExtensionType
	// SecretsManagerIdentity is the identity used for the secrets manager.
	SecretsManagerIdentity = "extension-" + ExtensionType

	extensionServiceName = "extension-" + ServiceName
	// ManagedResourceNamesSeed is the name used to describe the managed seed resources.
	ManagedResourceNamesSeed = extensionServiceName + "-seed"
	// ManagedResourceNamesShoot is the name used to describe the managed shoot resources.
	ManagedResourceNamesShoot = extensionServiceName + "-shoot"

	// ApplicationName is the name for resource describing the components deployed by the extension controller.
	ApplicationName = "oidc-webhook-authenticator"
	// ImageName is the name of the oidc webhook authenticator image.
	ImageName = ApplicationName
	// WebhookConfigurationName is the name of the webhook configuration(s) deployed in the shoot cluster.
	WebhookConfigurationName = ApplicationName + "-shoot"
	// WebhookTLSSecretName is the name of the TLS secret resource used by the OIDC webhook in the seed cluster.
	WebhookTLSSecretName = ApplicationName + "-tls"
	// WebhookTLSCertDir is the directory used for mounting the webhook certificates.
	WebhookTLSCertDir = "/var/run/oidc-webhook-authenticator/tls"
	// WebhookServiceAccountTokenDir is the directory used for mounting the projected service account token in the webhook authenticator pod.
	WebhookServiceAccountTokenDir = "/var/run/oidc-webhook-authenticator/serviceaccount"
	// WebhookKubeConfigSecretName is the name of the secret providing the kubeconfig for connection to the webhook authenticator.
	WebhookKubeConfigSecretName = ApplicationName + "-kubeconfig"
	// OIDCResourceReader is the name of the RBAC resources created in the shoot cluster that allow reading authentication.gardener.cloud.openidconnects.
	OIDCResourceReader = ApplicationName + "-resource-reader"
	// AuthDelegator is used to name the cluster role binding used for binding to "system:auth-delegator" cluster role in the shoot cluster.
	AuthDelegator = ApplicationName + "-auth-delegator"
	// ExtensionAuthReader is used to name the role binding used for binding to "extension-apiserver-authentication-reader" role in the kube-system namespace in the shoot cluster.
	ExtensionAuthReader = ApplicationName + "-authentication-reader"
	// TokenValidator is used to name the resources used to allow the kube-apiserver to validate tokens against the oidc authenticator.
	TokenValidator = ApplicationName + "-token-validator"
)
