// SPDX-FileCopyrightText: 2022 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

/**
	Overview
		- Tests the lifecycle controller for the shoot-oidc-service extension.
	Prerequisites
		- A Shoot exists and the oidc extension is available for the seed cluster.
**/

package lifecycle_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	"github.com/gardener/gardener/test/framework"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
)

func init() {
	framework.RegisterShootFrameworkFlags()
}

const (
	timeout = 30 * time.Minute
)

var _ = Describe("Shoot oidc service testing", func() {
	f := framework.NewShootFramework(nil)

	var initialExtensionConfig []gardencorev1beta1.Extension

	BeforeEach(func() {
		initialExtensionConfig = f.Shoot.Spec.Extensions
	})

	AfterEach(func() {
		// Revert to initial extension configuration
		err := f.UpdateShoot(context.Background(), func(shoot *gardencorev1beta1.Shoot) error {
			shoot.Spec.Extensions = initialExtensionConfig
			return nil
		})
		Expect(err).ToNot(HaveOccurred())
	})

	f.Serial().Beta().CIt("Should perform the common case scenario without any errors", func(ctx context.Context) {
		err := f.UpdateShoot(ctx, ensureOIDCServiceIsEnabled)
		Expect(err).ToNot(HaveOccurred())

		oidcDeployment := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ApplicationName,
				Namespace: f.ShootSeedNamespace(),
			},
		}

		By("Verify that the oidc deployment exists and is deployed with the correct number of replicas")
		Expect(f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(oidcDeployment), oidcDeployment)).To(Succeed())
		one := int32(1)
		Expect(oidcDeployment.Spec.Replicas).To(PointTo(BeNumerically(">=", one)))
		Expect(oidcDeployment.Status.ReadyReplicas).To(BeNumerically(">=", one))

		oidcPDB := &policyv1.PodDisruptionBudget{
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ApplicationName,
				Namespace: f.ShootSeedNamespace(),
			},
		}

		By("Verify that PodDisruptionBudget is correctly configured")
		Expect(err).NotTo(HaveOccurred())

		Expect(f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(oidcPDB), oidcPDB)).To(Succeed())
		Expect(oidcPDB.Spec.MaxUnavailable).To(PointTo(Equal(intstr.FromInt(1))))
		Expect(oidcPDB.Spec.UnhealthyPodEvictionPolicy).To(PointTo(Equal(policyv1.AlwaysAllow)))

		By("Check OIDC config")
		oidConfig, err := getOIDConfig(ctx, f.SeedClient.RESTClient())
		if err == nil {
			jwksURL, err := url.Parse(oidConfig.JWKSURL)
			Expect(err).ToNot(HaveOccurred())

			jwks, err := getJWKS(ctx, f.SeedClient.RESTClient(), jwksURL.Path)
			Expect(err).ToNot(HaveOccurred())
			clientID := "some-custom-client-id"
			oidcAPIVersion := "authentication.gardener.cloud/v1alpha1"
			oidcKind := "OpenIDConnect"

			// Deploy oidc resource
			oidc := &unstructured.Unstructured{}
			oidc.Object = map[string]interface{}{
				"apiVersion": oidcAPIVersion,
				"kind":       oidcKind,
				"metadata": map[string]interface{}{
					"name": "custom",
				},
				"spec": map[string]interface{}{
					"issuerURL":      oidConfig.Issuer,
					"clientID":       clientID,
					"usernameClaim":  "sub",
					"usernamePrefix": "custom-prefix:",
					"jwks": map[string]interface{}{
						"keys": jwks,
					},
				},
			}
			err = f.ShootClient.Client().Create(ctx, oidc, &client.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			oidc = &unstructured.Unstructured{}
			oidc.SetAPIVersion(oidcAPIVersion)
			oidc.SetKind(oidcKind)
			oidc.SetName("custom")
			err = f.ShootClient.Client().Get(ctx, client.ObjectKeyFromObject(oidc), oidc)
			Expect(err).ToNot(HaveOccurred())

			// Conversion should be safe
			spec := oidc.Object["spec"].(map[string]interface{})
			Expect(spec["clientID"]).To(Equal(clientID))
			Expect(spec["issuerURL"]).To(Equal(oidConfig.Issuer))

			// Get token from seed
			var ttl int64 = 1800
			tokenReq, err := f.SeedClient.Kubernetes().CoreV1().ServiceAccounts("default").CreateToken(ctx, "default", &authenticationv1.TokenRequest{
				Spec: authenticationv1.TokenRequestSpec{
					Audiences:         []string{clientID},
					ExpirationSeconds: &ttl,
				},
			}, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())

			expectedStatus := status{
				Status:  "Failure",
				Message: `forbidden: User "custom-prefix:system:serviceaccount:default:default" cannot get path "/"`,
				Reason:  "Forbidden",
				Code:    403,
			}

			// Expect API calls to be authenticated
			Eventually(func() status {
				statusError, err := requestAPIServer(ctx, f.ShootClient.RESTConfig().CAData, f.ShootClient.RESTConfig().Host, tokenReq.Status.Token)
				Expect(err).ToNot(HaveOccurred())

				return status{
					Code:    int(statusError.Code),
					Message: statusError.Message,
					Reason:  string(statusError.Reason),
					Status:  statusError.Status,
				}
			}, time.Second*20, time.Second).Should(Equal(expectedStatus))

			// Delete the oidc resource
			err = f.ShootClient.Client().Delete(ctx, oidc, &client.DeleteOptions{})
			Expect(err).ToNot(HaveOccurred())

			// Expect API calls to be unauthorized
			expectedStatus.Code = 401
			expectedStatus.Message = "Unauthorized"
			expectedStatus.Reason = string(metav1.StatusReasonUnauthorized)
			Eventually(func() status {
				statusError, err := requestAPIServer(ctx, f.ShootClient.RESTConfig().CAData, f.ShootClient.RESTConfig().Host, tokenReq.Status.Token)
				Expect(err).ToNot(HaveOccurred())

				return status{
					Code:    int(statusError.Code),
					Message: statusError.Message,
					Reason:  string(statusError.Reason),
					Status:  statusError.Status,
				}
			}, time.Second*20, time.Second).Should(Equal(expectedStatus))
		} else {
			f.Logger.Info(fmt.Sprintf("Cannot register the seed as identity provider. Error: %s. The verification of oidc provider registration was skipped. Continuing with test execution...", err.Error()))
		}

		By("Ensure that the OIDC service is disabled in order to verify the deletion process")
		err = f.UpdateShoot(ctx, ensureOIDCServiceIsDisabled)
		Expect(err).ToNot(HaveOccurred())

		By("Ensure that oidc authenticator deployment is deleted")
		err = f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(oidcDeployment), oidcDeployment)
		Expect(err).To(HaveOccurred())
		Expect(err).To(BeNotFoundError())

		By("Ensure that manually deployed secrets are deleted")
		for _, name := range []string{
			gutil.SecretNamePrefixShootAccess + constants.TokenValidator,
			gutil.SecretNamePrefixShootAccess + constants.ApplicationName,
		} {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: f.ShootSeedNamespace(),
				},
			}
			err = f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(secret), secret)
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeNotFoundError())
		}
	}, timeout)
})

func ensureOIDCServiceIsEnabled(shoot *gardencorev1beta1.Shoot) error {
	for i, e := range shoot.Spec.Extensions {
		if e.Type == constants.ExtensionType {
			if e.Disabled != nil && *e.Disabled == true {
				shoot.Spec.Extensions[i].Disabled = ptr.To(false)
			}
			return nil
		}
	}

	shoot.Spec.Extensions = append(shoot.Spec.Extensions, gardencorev1beta1.Extension{
		Type:     constants.ExtensionType,
		Disabled: ptr.To(false),
	})
	return nil
}

func ensureOIDCServiceIsDisabled(shoot *gardencorev1beta1.Shoot) error {
	for i, e := range shoot.Spec.Extensions {
		if e.Type == constants.ExtensionType {
			shoot.Spec.Extensions[i].Disabled = ptr.To(true)
			return nil
		}
	}
	return nil
}

type oidConfig struct {
	Issuer                 string   `json:"issuer,omitempty"`
	JWKSURL                string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported []string `json:"response_types_supported,omitempty"`
	SubjectTypesSupported  []string `json:"subject_types_supported,omitempty"`
	SigningAlgsSupported   []string `json:"id_token_signing_alg_values_supported,omitempty"`
}

func getOIDConfig(ctx context.Context, client rest.Interface) (*oidConfig, error) {
	oidReq := client.Get()
	oidReq.RequestURI("/.well-known/openid-configuration")
	respBytes, err := oidReq.DoRaw(ctx)
	if err != nil {
		return nil, err
	}

	oidConfig := &oidConfig{}
	err = json.Unmarshal(respBytes, oidConfig)
	if err != nil {
		return nil, err
	}
	return oidConfig, nil
}

func getJWKS(ctx context.Context, client rest.Interface, relativeURI string) ([]byte, error) {
	jwksReq := client.Get()
	jwksReq.RequestURI(relativeURI)
	return jwksReq.DoRaw(ctx)
}

func requestAPIServer(ctx context.Context, caBundle []byte, apiserverURL, bearerToken string) (*metav1.Status, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiserverURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caBundle)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	status := &metav1.Status{}
	err = json.Unmarshal(body, status)
	if err != nil {
		return nil, err
	}

	err = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return status, nil
}

type status struct {
	Code    int
	Message string
	Reason  string
	Status  string
}
