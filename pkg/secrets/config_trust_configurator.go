// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	secretutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
)

const (
	// ManagerIdentityShootTrustRuntime is the identity used for the secrets manager when extension is with class garden.
	ManagerIdentityShootTrustRuntime = "extension-" + constants.ExtensionTypeGardenShootTrustConfigurator + "-runtime"
	// ShootTrustCAName is the name of the CA secret.
	ShootTrustCAName = "ca-extension-" + constants.ExtensionTypeGardenShootTrustConfigurator
)

// ShootTrustConfigsFor returns configurations for the secrets manager for the given namespace.
func ShootTrustConfigsFor(namespace string) []extensionssecretsmanager.SecretConfigWithOptions {
	return []extensionssecretsmanager.SecretConfigWithOptions{
		{
			Config: &secretutils.CertificateSecretConfig{
				Name:       ShootTrustCAName,
				CommonName: ShootTrustCAName,
				CertType:   secretutils.CACert,
			},
			Options: []secretsmanager.GenerateOption{secretsmanager.Persist()},
		},
		{
			Config: &secretutils.CertificateSecretConfig{
				Name:                        constants.WebhookTLSSecretNameGardenShootTrustConfigurator,
				CommonName:                  constants.ApplicationNameGardenShootTrustConfigurator,
				DNSNames:                    kutil.DNSNamesForService(constants.ApplicationNameGardenShootTrustConfigurator, namespace),
				CertType:                    secretutils.ServerCert,
				SkipPublishingCACertificate: true,
			},
			// use current CA for signing server cert to prevent mismatches when dropping the old CA from the webhook
			// config in phase Completing
			Options: []secretsmanager.GenerateOption{secretsmanager.SignedByCA(ShootTrustCAName, secretsmanager.UseCurrentCA)},
		},
	}
}
