// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	// ApplicationName is the name for resource describing the components deployed by the extension controller.
	ApplicationName = "oidc-webhook-authenticator"
	// WebhookConfigurationName is the name of the webhook configuration(s) deployed in the shoot cluster.
	WebhookConfigurationName = ApplicationName + "-shoot"
	// WebhookTLSecretName is the name of the TLS secret resource used by the OIDC webhook in the seed cluster.
	WebhookTLSecretName = ApplicationName + "-tls"
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
