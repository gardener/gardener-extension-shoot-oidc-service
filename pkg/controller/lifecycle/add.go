// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/extension"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
)

const (
	// Type is the type of Extension resource.
	Type = constants.ExtensionType
	// Name is the name of the lifecycle controller.
	Name = "shoot_oidc_service_lifecycle_controller"
	// FinalizerSuffix is the finalizer suffix for the OIDC Service controller.
	FinalizerSuffix = constants.ExtensionType
)

// DefaultAddOptions contains configuration for the OIDC service.
var DefaultAddOptions = AddOptions{}

// AddOptions are options to apply when adding the oidc service controller to the manager.
type AddOptions struct {
	// ControllerOptions contains options for the controller.
	ControllerOptions controller.Options
	// IgnoreOperationAnnotation specifies whether to ignore the operation annotation or not.
	IgnoreOperationAnnotation bool
	// ExtensionClasses contains the extension classes the controller should reconcile.
	// Only a single type of extension class is supported at the moment.
	// Depending on the extension class, the controller will target shoot control plane or garden namespaces.
	ExtensionClasses []extensionsv1alpha1.ExtensionClass
}

// AddToManager adds a OIDC Service Lifecycle controller to the given Controller Manager.
func AddToManager(ctx context.Context, mgr manager.Manager) error {
	return extension.Add(mgr, extension.AddArgs{
		Actuator:          NewActuator(mgr),
		ControllerOptions: DefaultAddOptions.ControllerOptions,
		ExtensionClasses:  DefaultAddOptions.ExtensionClasses,
		Name:              Name,
		FinalizerSuffix:   FinalizerSuffix,
		Resync:            60 * time.Minute,
		Predicates:        extension.DefaultPredicates(ctx, mgr, DefaultAddOptions.IgnoreOperationAnnotation),
		Type:              constants.ExtensionType,
	})
}
