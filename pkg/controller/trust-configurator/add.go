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
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
)

const (
	// Type is the second type of Extension resource.
	Type = constants.ExtensionTypeGardenShootTrustConfigurator
	// Name is the name of the garden shoot trust configurator controller.
	Name = constants.ExtensionTypeGardenShootTrustConfigurator
	// FinalizerSuffix is the finalizer suffix for the garden shoot trust configurator controller.
	FinalizerSuffix = constants.ExtensionTypeGardenShootTrustConfigurator
)

// DefaultAddOptions are the default AddOptions for AddToManager.
var DefaultAddOptions = AddOptions{}

// AddOptions are options to apply when adding the oidc service controller to the manager.
type AddOptions struct {
	// ControllerOptions contains options for the controller.
	ControllerOptions controller.Options
	// ExtensionClasses contains the extension classes the controller should reconcile.
	// Only the garden extension class is supported for this controller.
	ExtensionClasses []extensionsv1alpha1.ExtensionClass
	// IgnoreOperationAnnotation specifies whether to ignore the operation annotation or not.
	IgnoreOperationAnnotation bool
	// OIDCConfig contains the OIDC configuration for the trust configurator.
	OIDCConfig configv1alpha1.OIDCConfig
}

// AddToManager adds a second controller with the default Options to the given Controller Manager.
func AddToManager(ctx context.Context, mgr manager.Manager) error {
	return AddToManagerWithOptions(ctx, mgr, DefaultAddOptions)
}

// AddToManagerWithOptions adds a second controller with the given Options to the given manager.
func AddToManagerWithOptions(ctx context.Context, mgr manager.Manager, opts AddOptions) error {
	if len(opts.ExtensionClasses) != 1 || opts.ExtensionClasses[0] != extensionsv1alpha1.ExtensionClassGarden {
		return fmt.Errorf("extension class %q is not supported for extension type %q", opts.ExtensionClasses, Type)
	}

	return extension.Add(mgr, extension.AddArgs{
		Actuator:          NewActuator(mgr, opts.OIDCConfig),
		ControllerOptions: opts.ControllerOptions,
		ExtensionClasses:  opts.ExtensionClasses,
		Name:              Name,
		FinalizerSuffix:   FinalizerSuffix,
		Resync:            60 * time.Minute,
		Predicates:        extension.DefaultPredicates(ctx, mgr, opts.IgnoreOperationAnnotation),
		Type:              Type,
	})
}
