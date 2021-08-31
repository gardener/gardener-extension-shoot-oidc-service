# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# builder
FROM eu.gcr.io/gardener-project/3rd/golang:1.16.5 AS builder

WORKDIR /go/src/github.com/gardener/gardener-extension-shoot-oidc-service
COPY . .
RUN make install

############# gardener-extension-shoot-oidc-service
FROM eu.gcr.io/gardener-project/3rd/alpine:3.13.5 AS gardener-extension-shoot-oidc-service

COPY charts /charts
COPY --from=builder /go/bin/gardener-extension-shoot-oidc-service /gardener-extension-shoot-oidc-service
ENTRYPOINT ["/gardener-extension-shoot-oidc-service"]
