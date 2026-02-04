// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"fmt"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	extensionssecretsmanager "github.com/gardener/gardener/extensions/pkg/util/secret/manager"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1/helper"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	"github.com/gardener/gardener/pkg/extensions"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/kubernetes/health"
	"github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/retry"
	secretsutils "github.com/gardener/gardener/pkg/utils/secrets"
	secretsmanager "github.com/gardener/gardener/pkg/utils/secrets/manager"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/secrets"
)

const (
	// ActuatorName is the name of the OIDC Service actuator.
	ActuatorName = constants.ServiceName + "-actuator"

	// initialOIDCReplicaCount is the initial number of OIDC webhook replicas
	initialOIDCReplicaCount int32 = 2

	// fakeTokenSecretName is a temporary constant for a secret that was used in older versions
	fakeTokenSecretName = constants.ApplicationName + "-fake-token" // <- TODO: remove this constant in a future release

	// virtualGardenPrefix is the prefix for virtual garden deployments
	virtualGardenPrefix = "virtual-garden-"
)

// NewActuator returns an actuator responsible for Extension resources.
func NewActuator(mgr manager.Manager) extension.Actuator {
	return &actuator{
		client: mgr.GetClient(),
		reader: mgr.GetAPIReader(),
	}
}

type actuator struct {
	client client.Client
	reader client.Reader
}

// clusterContext contains cluster-specific settings extracted based on the extension class (shoot or garden).
type clusterContext struct {
	hibernated                  bool
	namespace                   string
	genericTokenKubeconfigName  string
	kubeAPIServerDeploymentName string
	secretsManager              secretsmanager.Interface
}

// Reconcile the Extension resource.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	var (
		clusterCtx *clusterContext
		err        error
	)

	extensionClass := extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.GetExtensionClass())
	switch extensionClass {
	case extensionsv1alpha1.ExtensionClassShoot:
		clusterCtx, err = a.buildShootClusterContext(ctx, log, ex)
		if err != nil {
			return err
		}
	case extensionsv1alpha1.ExtensionClassGarden:
		clusterCtx, err = a.buildGardenClusterContext(ctx, log, ex)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported extension class: %s", extensionClass)
	}

	oidcShootAccessSecret := gutil.NewShootAccessSecret(gutil.SecretNamePrefixShootAccess+constants.ApplicationName, clusterCtx.namespace)
	if err := oidcShootAccessSecret.Reconcile(ctx, a.client); err != nil {
		return err
	}

	oidcReplicas, err := a.getOIDCReplicas(ctx, clusterCtx)
	if err != nil {
		return err
	}

	configs := secrets.ConfigsFor(clusterCtx.namespace)
	generatedSecrets, err := extensionssecretsmanager.GenerateAllSecrets(ctx, clusterCtx.secretsManager, configs)
	if err != nil {
		return err
	}

	caBundleSecret, found := clusterCtx.secretsManager.Get(secrets.CAName)
	if !found {
		return fmt.Errorf("secret %q not found", secrets.CAName)
	}

	seedResources, err := getSeedResources(
		oidcReplicas,
		clusterCtx.namespace,
		clusterCtx.genericTokenKubeconfigName,
		oidcShootAccessSecret.Secret.Name,
		generatedSecrets[constants.WebhookTLSSecretName].Name,
		clusterCtx.kubeAPIServerDeploymentName,
		extensionClass,
	)
	if err != nil {
		return err
	}

	shootResources, err := getShootResources(
		caBundleSecret.Data[secretsutils.DataKeyCertificateBundle],
		clusterCtx.namespace,
		oidcShootAccessSecret.ServiceAccountName,
	)
	if err != nil {
		return err
	}

	if err := managedresources.CreateForShoot(ctx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesShoot, constants.ServiceName, false, shootResources); err != nil {
		return err
	}

	if err := managedresources.CreateForSeed(ctx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesSeed, false, seedResources); err != nil {
		return err
	}

	twoMinutes := 2 * time.Minute
	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelSeedCtx()
	if err := managedresources.WaitUntilHealthy(timeoutSeedCtx, a.client, clusterCtx.namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	oidcDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationName,
			Namespace: clusterCtx.namespace,
		},
	}
	timeoutRolloutCtx, cancelWaitRollout := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelWaitRollout()
	if err := retry.Until(timeoutRolloutCtx, 5*time.Second, health.IsDeploymentUpdated(a.reader, oidcDeployment)); err != nil {
		return err
	}

	// Patch the kube-apiserver (or virtual-garden-kube-apiserver) deployment to trigger the webhook
	depl := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clusterCtx.namespace,
			Name:      clusterCtx.kubeAPIServerDeploymentName,
		},
	}
	if err := a.client.Patch(ctx, depl, client.RawPatch(types.StrategicMergePatchType, []byte("{}"))); err != nil {
		return err
	}

	// TODO: remove this in a future release
	if err := a.deleteSecret(ctx, fakeTokenSecretName, clusterCtx.namespace); err != nil {
		return err
	}

	return clusterCtx.secretsManager.Cleanup(ctx)
}

// buildShootClusterContext extracts cluster info for extensions with shoot extension class
func (a *actuator) buildShootClusterContext(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) (*clusterContext, error) {
	namespace := ex.GetNamespace()

	cluster, err := controller.GetCluster(ctx, a.client, namespace)
	if err != nil {
		return nil, err
	}

	configs := secrets.ConfigsFor(namespace)
	secretsManager, err := extensionssecretsmanager.SecretsManagerForCluster(
		ctx,
		log.WithName("secretsmanager"),
		clock.RealClock{},
		a.client,
		cluster,
		secrets.ManagerIdentity,
		configs,
	)
	if err != nil {
		return nil, err
	}

	return &clusterContext{
		namespace:                   namespace,
		genericTokenKubeconfigName:  extensions.GenericTokenKubeconfigSecretNameFromCluster(cluster),
		kubeAPIServerDeploymentName: v1beta1constants.DeploymentNameKubeAPIServer,
		hibernated:                  controller.IsHibernationEnabled(cluster),
		secretsManager:              secretsManager,
	}, nil
}

// buildGardenClusterContext extracts cluster info for extensions with garden extension class
func (a *actuator) buildGardenClusterContext(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) (*clusterContext, error) {
	namespace := ex.GetNamespace()

	garden, err := a.getGarden(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get garden: %w", err)
	}

	genericTokenKubeconfigName, ok := garden.Annotations[v1beta1constants.AnnotationKeyGenericTokenKubeconfigSecretName]
	if !ok {
		return nil, fmt.Errorf("no generic token kubeconfig secret found in garden object annotations")
	}

	configs := secrets.ConfigsFor(namespace)
	secretsManager, err := extensionssecretsmanager.SecretsManagerForGarden(
		ctx,
		log.WithName("secretsmanager"),
		clock.RealClock{},
		a.client,
		garden,
		secrets.ManagerIdentityRuntime,
		configs,
		namespace,
	)
	if err != nil {
		return nil, err
	}

	return &clusterContext{
		namespace:                   namespace,
		genericTokenKubeconfigName:  genericTokenKubeconfigName,
		kubeAPIServerDeploymentName: virtualGardenPrefix + v1beta1constants.DeploymentNameKubeAPIServer,
		hibernated:                  false,
		secretsManager:              secretsManager,
	}, nil
}

// Delete the Extension resource.
func (a *actuator) Delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension) error {
	return a.delete(ctx, log, ex, false)
}

// delete deletes the resources deployed for the extension.
// It can be configured to skip deletion of the secrets managed by the SecretsManager.
func (a *actuator) delete(ctx context.Context, log logr.Logger, ex *extensionsv1alpha1.Extension, skipSecretsManagerSecrets bool) error {
	namespace := ex.GetNamespace()
	twoMinutes := 2 * time.Minute

	timeoutSeedCtx, cancelSeedCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelSeedCtx()

	if err := managedresources.DeleteForSeed(ctx, a.client, namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutSeedCtx, a.client, namespace, constants.ManagedResourceNamesSeed); err != nil {
		return err
	}

	timeoutShootCtx, cancelShootCtx := context.WithTimeout(ctx, twoMinutes)
	defer cancelShootCtx()

	if err := managedresources.DeleteForShoot(ctx, a.client, namespace, constants.ManagedResourceNamesShoot); err != nil {
		return err
	}

	if err := managedresources.WaitUntilDeleted(timeoutShootCtx, a.client, namespace, constants.ManagedResourceNamesShoot); err != nil {
		return err
	}

	for _, name := range []string{
		gutil.SecretNamePrefixShootAccess + constants.TokenValidator, // <- TODO: remove the secret name in a future version
		gutil.SecretNamePrefixShootAccess + constants.ApplicationName,
		fakeTokenSecretName, // <- TODO: remove the secret name in a future release
	} {
		if err := a.deleteSecret(ctx, name, namespace); err != nil {
			return err
		}
	}

	if skipSecretsManagerSecrets {
		return nil
	}

	// Based on the extension class initialize the appropriate SecretsManager
	extensionClass := extensionsv1alpha1helper.GetExtensionClassOrDefault(ex.Spec.GetExtensionClass())
	var secretsManager secretsmanager.Interface
	switch extensionClass {
	case extensionsv1alpha1.ExtensionClassShoot:
		cluster, err := controller.GetCluster(ctx, a.client, namespace)
		if err != nil {
			return err
		}

		secretsManager, err = extensionssecretsmanager.SecretsManagerForCluster(ctx, log.WithName("secretsmanager"), clock.RealClock{}, a.client, cluster, secrets.ManagerIdentity, nil)
		if err != nil {
			return err
		}
	case extensionsv1alpha1.ExtensionClassGarden:
		garden, err := a.getGarden(ctx)
		if err != nil {
			return fmt.Errorf("failed to get garden: %w", err)
		}

		secretsManager, err = extensionssecretsmanager.SecretsManagerForGarden(ctx, log.WithName("secretsmanager"), clock.RealClock{}, a.client, garden, secrets.ManagerIdentityRuntime, nil, namespace)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported extension class: %s", extensionClass)
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
	if err := managedresources.SetKeepObjects(ctx, a.client, ex.GetNamespace(), constants.ManagedResourceNamesShoot, true); err != nil {
		return err
	}

	// SecretsManager secrets should not be deleted during migration in order to have the required ones
	// persisted in the shootstate resource.
	return a.delete(ctx, log, ex, true)
}

func (a *actuator) getOIDCReplicas(ctx context.Context, clusterCtx *clusterContext) (*int32, error) {
	// Scale to 0 if cluster is hibernated
	if clusterCtx.hibernated {
		return ptr.To[int32](0), nil
	}

	oidcDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      constants.ApplicationName,
			Namespace: clusterCtx.namespace,
		},
	}

	err := a.client.Get(ctx, client.ObjectKeyFromObject(oidcDeployment), oidcDeployment)

	switch {
	case err != nil && apierrors.IsNotFound(err):
		// Scale to initial replica count
		return ptr.To(initialOIDCReplicaCount), nil
	case err != nil:
		// Error cannot be handled here so pass it to the caller function
		return ptr.To[int32](0), err
	case oidcDeployment.Spec.Replicas != nil && *oidcDeployment.Spec.Replicas > 0:
		// Do not interfere with hpa recommendations
		return oidcDeployment.Spec.Replicas, nil
	case oidcDeployment.Spec.Replicas != nil && *oidcDeployment.Spec.Replicas == 0:
		// Wake up oidc deployment with initial replica count
		return ptr.To(initialOIDCReplicaCount), nil
	default:
		return ptr.To(initialOIDCReplicaCount), nil
	}
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
