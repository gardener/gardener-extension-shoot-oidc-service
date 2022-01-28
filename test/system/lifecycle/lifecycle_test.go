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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/gardener/gardener-extension-shoot-oidc-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-oidc-service/test/system/resources/templates"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gutil "github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/test/framework"

	appsv1 "k8s.io/api/apps/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	framework.RegisterShootFrameworkFlags()
}

const (
	timeout = 30 * time.Minute
)

var _ = Describe("Shoot oidc service testing", func() {
	f := framework.NewShootFramework(nil)
	f.ResourcesDir = "../resources"

	f.Serial().Release().CIt("Should perform the common case scenario without any errors", func(ctx context.Context) {
		err := f.UpdateShoot(ctx, func(shoot *gardencorev1beta1.Shoot) error {
			if !isOIDCServiceEnabled(shoot) {
				shoot.Spec.Extensions = append(shoot.Spec.Extensions, gardencorev1beta1.Extension{
					Type: constants.ExtensionType,
				})
			}
			return nil
		})
		Expect(err).ToNot(HaveOccurred())

		oidcDeployment := &appsv1.Deployment{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name:      constants.ApplicationName,
				Namespace: f.ShootSeedNamespace(),
			},
		}

		// Verify that the oidc deployment exists and is deployed with the correct number of replicas
		err = f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(oidcDeployment), oidcDeployment)
		Expect(err).ToNot(HaveOccurred())
		one := int32(1)
		Expect(*oidcDeployment.Spec.Replicas).To(Equal(one))
		Expect(oidcDeployment.Status.ReadyReplicas).To(Equal(one))

		oidConfig, err := getOIDConfig(ctx, f.SeedClient.RESTClient())
		Expect(err).ToNot(HaveOccurred())

		jwksURL, err := url.Parse(oidConfig.JWKSURL)
		Expect(err).ToNot(HaveOccurred())

		jwks, err := getJWKS(ctx, f.SeedClient.RESTClient(), jwksURL.Path)
		Expect(err).ToNot(HaveOccurred())

		// Deploy oidc resource
		clientId := "some-custom-client-id"
		values := map[string]interface{}{
			"issuerURL": oidConfig.Issuer,
			"clientID":  clientId,
			"keys":      base64.StdEncoding.EncodeToString(jwks),
		}
		err = f.RenderAndDeployTemplate(ctx, f.ShootClient, templates.CustomOIDCConfiguration, values)
		Expect(err).ToNot(HaveOccurred())
		getRequest := f.ShootClient.RESTClient().Get()
		getRequest = getRequest.RequestURI("/apis/authentication.gardener.cloud/v1alpha1/openidconnects/custom")
		getResponse := getRequest.Do(ctx)
		Expect(getResponse.Error()).ToNot(HaveOccurred())

		statusCode := 0
		getResponse.StatusCode(&statusCode)
		Expect(statusCode).To(Equal(200))

		// Get token from seed
		var ttl int64 = 1800
		tokenReq, err := f.SeedClient.Kubernetes().CoreV1().ServiceAccounts("default").CreateToken(ctx, "default", &authenticationv1.TokenRequest{
			Spec: authenticationv1.TokenRequestSpec{
				Audiences:         []string{clientId},
				ExpirationSeconds: &ttl,
			},
		}, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())

		expectedStatus := status{
			Status:  "Failure",
			Message: "forbidden: User \"custom-prefix:system:serviceaccount:default:default\" cannot get path \"/\"",
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
		deleteRequest := f.ShootClient.RESTClient().Delete()
		deleteRequest = deleteRequest.RequestURI("/apis/authentication.gardener.cloud/v1alpha1/openidconnects/custom")
		deleteResponse := deleteRequest.Do(ctx)
		Expect(deleteResponse.Error()).ToNot(HaveOccurred())
		getResponse.StatusCode(&statusCode)
		Expect(statusCode).To(Equal(200))

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

		// Disable the OIDC extension
		err = f.UpdateShoot(ctx, func(shoot *gardencorev1beta1.Shoot) error {
			newExtensions := make([]gardencorev1beta1.Extension, len(shoot.Spec.Extensions)-1)
			for _, e := range shoot.Spec.Extensions {
				if e.Type != constants.ExtensionType {
					newExtensions = append(newExtensions, e)
				}
			}
			shoot.Spec.Extensions = newExtensions
			return nil
		})
		Expect(err).ToNot(HaveOccurred())

		// Ensure that oidc authenticator deployment is deleted
		err = f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(oidcDeployment), oidcDeployment)
		Expect(err).To(HaveOccurred())
		Expect(apierrors.IsNotFound(err)).To(BeTrue())

		// Ensure that manually deployed secrets are deleted
		for _, name := range []string{
			gutil.SecretNamePrefixShootAccess + constants.TokenValidator,
			gutil.SecretNamePrefixShootAccess + constants.ApplicationName,
			constants.WebhookTLSecretName,
		} {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: f.ShootSeedNamespace(),
				},
			}
			err = f.SeedClient.Client().Get(ctx, client.ObjectKeyFromObject(secret), secret)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		}
	}, timeout)
})

func isOIDCServiceEnabled(shoot *gardencorev1beta1.Shoot) bool {
	for _, e := range shoot.Spec.Extensions {
		if e.Type == constants.ExtensionType && (e.Disabled == nil || *e.Disabled == false) {
			return true
		}
	}
	return false
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

func getJWKS(ctx context.Context, client rest.Interface, relativeUri string) ([]byte, error) {
	jwksReq := client.Get()
	jwksReq.RequestURI(relativeUri)
	return jwksReq.DoRaw(ctx)
}

func requestAPIServer(ctx context.Context, caBundle []byte, apiserverURL, bearerToken string) (*metav1.Status, error) {
	req, err := http.NewRequest("GET", apiserverURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", bearerToken))

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caBundle)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	status := &metav1.Status{}
	err = json.Unmarshal(body, status)
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
