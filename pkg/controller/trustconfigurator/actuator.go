// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package trustconfigurator

import (
	"context"
	"fmt"
	"time"

	configv1alpha1 "github.com/gardener/garden-shoot-trust-configurator/pkg/apis/config/v1alpha1"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/api/extensions/v1alpha1/helper"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/kubernetes/health"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/retry"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/secrets"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(mgr manager.Manager, oidcConfig configv1alpha1.OIDCConfig) extension.Actuator {
	return &actuator{
		client:     mgr.GetClient(),
		reader:     mgr.GetAPIReader(),
		oidcConfig: oidcConfig,
	}
}

type actuator struct {
	client     client.Client
	reader     client.Reader
	oidcConfig configv1alpha1.OIDCConfig
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	extensionClass := extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.GetExtensionClass())
	if extensionClass != extensionsv1alpha1.ExtensionClassGarden {
		return fmt.Errorf("unsupported extension class: %s", extensionClass)
	}

	garden, err := a.getGarden(ctx)
	if err != nil {
		return fmt.Errorf("failed to get garden: %w", err)
	}

	genericTokenKubeconfigName, ok := garden.Annotations[v1beta1constants.AnnotationKeyGenericTokenKubeconfigSecretName]
	if !ok {
		return fmt.Errorf("no generic token kubeconfig secret found in garden object annotations")
	}

	namespace := ex.GetNamespace()
	configs := secrets.ShootTrustConfigsFor(namespace)
	secretsManager, err := extensionssecretsmanager.SecretsManagerForGarden(
		ctx,
		log.WithName("secretsmanager"),
		clock.RealClock{},
		a.client,
		garden,
		secrets.ManagerIdentityShootTrustRuntime,
		configs,
		namespace,
	)
	if err != nil {
		return err
	}

	gardenAccessSecret := gutil.NewShootAccessSecret(gutil.SecretNamePrefixShootAccess+constants.GardenShootTrustConfiguratorApplicationName, namespace)
	if err := gardenAccessSecret.Reconcile(ctx, a.client); err != nil {
		return err
	}

	generatedSecrets, err := extensionssecretsmanager.GenerateAllSecrets(ctx, secretsManager, configs)
	if err != nil {
		return err
	}

	caBundleSecret, found := secretsManager.Get(secrets.ShootTrustCAName)
	if !found {
		return fmt.Errorf("secret %q not found", secrets.ShootTrustCAName)
	}

	sourceResources, err := getSourceResources(
		a.oidcConfig,
		namespace,
		genericTokenKubeconfigName,
		gardenAccessSecret.Secret.Name,
		generatedSecrets[constants.GardenShootTrustConfiguratorWebhookTLSSecretName].Name,
	)
	if err != nil {
		return err
	}

	targetResources, err := getTargetResources(
		caBundleSecret.Data[secretsutils.DataKeyCertificateBundle],
		namespace,
		gardenAccessSecret.ServiceAccountName,
	)
	if err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx, a.client, namespace, constants.GardenShootTrustConfiguratorManagedResourceNamesTarget, constants.GardenShootTrustConfiguratorServiceName, false, targetResources); err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, a.client, namespace, constants.GardenShootTrustConfiguratorManagedResourceNamesSource, false, sourceResources); err != nil {
		return err
	}

	twoMinutes := 2 * time.Minute
	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelSeedCtx()
	if err := managedresources.WaitUntilHealthy(timeoutSeedCtx, a.client, namespace, constants.GardenShootTrustConfiguratorManagedResourceNamesSource); err != nil {
		return err
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.GardenShootTrustConfiguratorApplicationName,
			Namespace: namespace,
		},
	}
	timeoutRolloutCtx, cancelWaitRollout := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelWaitRollout()
	if err := retry.Until(timeoutRolloutCtx, 5*time.Second, health.IsDeploymentUpdated(a.reader, deployment)); err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.delete(ctx, log, ex, false)
}

// delete deletes the resources deployed for the extension.
// It can be configured to skip deletion of the secrets managed by the SecretsManager.
func (a *actuator) delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension, skipSecretsManagerSecrets bool) error {
	extensionClass := extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.GetExtensionClass())
	if extensionClass != extensionsv1alpha1.ExtensionClassGarden {
		return fmt.Errorf("unsupported extension class: %s", extensionClass)
	}

	garden, err := a.getGarden(ctx)
	if err != nil {
		return fmt.Errorf("failed to get garden: %w", err)
	}

	twoMinutes := 2 * time.Minute
	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelSeedCtx()

	namespace := ex.GetNamespace()
	if err := managedresources.DeleteForSeed(ctx, a.client, namespace, constants.GardenShootTrustConfiguratorManagedResourceNamesSource); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutSeedCtx, a.client, namespace, constants.GardenShootTrustConfiguratorManagedResourceNamesSource); err != nil {
		return err
	}

	timeoutShootCtx, cancelShootCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelShootCtx()

	if err := managedresources.DeleteForShoot(ctx, a.client, namespace, constants.GardenShootTrustConfiguratorManagedResourceNamesTarget); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutShootCtx, a.client, namespace, constants.GardenShootTrustConfiguratorManagedResourceNamesTarget); err != nil {
		return err
	}

	if err := a.deleteSecret(ctx, gutil.SecretNamePrefixShootAccess+constants.GardenShootTrustConfiguratorApplicationName, namespace); err != nil {
		return err
	}

	if skipSecretsManagerSecrets {
		return nil
	}

	secretsManager, err := extensionssecretsmanager.SecretsManagerForGarden(ctx, log.WithName("secretsmanager"), clock.RealClock{}, a.client, garden, secrets.ManagerIdentityShootTrustRuntime, nil, namespace)
	if err != nil {
		return err
	}

	return secretsManager.Cleanup(ctx)
}

func (a *actuator) deleteSecret(ctx context.Context, name, namespace string) error {
	return client.IgnoreNotFound(a.client.Delete(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}))
}

// ForceDelete the Extension resource.
func (a *actuator) ForceDelete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Delete(ctx, log, ex)
}

// Restore the Extension resource.
func (a *actuator) Restore(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.Reconcile(ctx, log, ex)
}

// Migrate the Extension resource.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	// Keep objects for shoot managed resources so that they are not deleted from the shoot during the migration
	if err := managedresources.SetKeepObjects(ctx, a.client, ex.GetNamespace(), constants.GardenShootTrustConfiguratorManagedResourceNamesTarget, true); err != nil {
		return err
	}

	// SecretsManager secrets should not be deleted during migration in order to have the required ones
	// persisted in the shootstate resource.
	return a.delete(ctx, log, ex, true)
}

func (a *actuator) getGarden(ctx context.Context) (*operatorv1alpha1.Garden, error) {
	gardenList := &operatorv1alpha1.GardenList{}
	if err := a.client.List(ctx, gardenList); err != nil {
		return nil, err
	}

	if len(gardenList.Items) == 0 {
		return nil, fmt.Errorf("no garden object found")
	}

	if len(gardenList.Items) > 1 {
		return nil, fmt.Errorf("found more than one garden object")
	}

	return &gardenList.Items[0], nil
}
