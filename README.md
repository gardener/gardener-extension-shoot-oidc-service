# [Gardener Extension for openid connect services](https://gardener.cloud)

[![reuse compliant](https://reuse.software/badge/reuse-compliant.svg)](https://reuse.software/)

Project Gardener implements the automated management and operation of [Kubernetes](https://kubernetes.io/) clusters as a service.
Its main principle is to leverage Kubernetes concepts for all of its tasks.

Recently, most of the vendor specific logic has been developed [in-tree](https://github.com/gardener/gardener).
However, the project has grown to a size where it is very hard to extend, maintain, and test.
With [GEP-1](https://github.com/gardener/gardener/blob/master/docs/proposals/01-extensibility.md) we have proposed how the architecture can be changed in a way to support external controllers that contain their very own vendor specifics.
This way, we can keep Gardener core clean and independent.

This controller implements Gardener's extension contract for the `shoot-oidc-service` extension.

An example for a `ControllerRegistration` resource that can be used to register this controller to Gardener can be found [here](example/controller-registration.yaml).

Please find more information regarding the extensibility concepts and a detailed proposal [here](https://github.com/gardener/gardener/blob/master/docs/proposals/01-extensibility.md).

## Compatibility

The following lists known compatibility issues of this extension controller with other Gardener components.

| OIDC Extension | Gardener | Action | Notes |
| ------------- | -------- | ------ |  --- |
| `>= v0.15.0` | `>= 1.60.0 <v1.63.0` | Please update Gardener components to `>= v1.63.0` | A typically side-effect of running this combination is an unexpected scale-down of the OIDC webhook from `2 -> 1`. |
----

## Extension Resources

Example extension resource:

```yaml
apiVersion: extensions.gardener.cloud/v1alpha1
kind: Extension
metadata:
  name: extension-shoot-oidc-service
  namespace: shoot--project--abc
spec:
  type: shoot-oidc-service
```

When an extension resource is reconciled, the extension controller will create an instance of [OIDC Webhook Authenticator](https://github.com/gardener/oidc-webhook-authenticator). These resources are placed inside the shoot namespace on the seed. Also, the controller takes care about generating necessary `RBAC` resources for the seed as well as for the shoot.

Please note, this extension controller relies on the [Gardener-Resource-Manager](https://github.com/gardener/gardener/blob/master/docs/concepts/resource-manager.md) to deploy k8s resources to seed and shoot clusters.

## How to start using or developing this extension controller locally

You can run the controller locally on your machine by executing `make start`.

We are using Go modules for Golang package dependency management and [Ginkgo](https://github.com/onsi/ginkgo)/[Gomega](https://github.com/onsi/gomega) for testing.

## Feedback and Support

Feedback and contributions are always welcome. Please report bugs or suggestions as [GitHub issues](https://github.com/gardener/gardener-extension-shoot-oidc-service/issues) or join our [Slack channel #gardener](https://kubernetes.slack.com/messages/gardener) (please invite yourself to the Kubernetes workspace [here](http://slack.k8s.io)).

## Learn more!

Please find further resources about out project here:

* [Our landing page gardener.cloud](https://gardener.cloud/)
* ["Gardener, the Kubernetes Botanist" blog on kubernetes.io](https://kubernetes.io/blog/2018/05/17/gardener/)
* ["Gardener Project Update" blog on kubernetes.io](https://kubernetes.io/blog/2019/12/02/gardener-project-update/)
* [GEP-1 (Gardener Enhancement Proposal) on extensibility](https://github.com/gardener/gardener/blob/master/docs/proposals/01-extensibility.md)
* [Extensibility API documentation](https://github.com/gardener/gardener/tree/master/docs/extensions)
* [Gardener Extensions Golang library](https://godoc.org/github.com/gardener/gardener/extensions/pkg)
* [Gardener API Reference](https://gardener.cloud/api-reference/)
