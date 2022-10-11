# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# builder
FROM golang:1.19.2 AS builder

WORKDIR /go/src/github.com/gardener/gardener-extension-shoot-oidc-service
COPY . .
RUN make install

############# gardener-extension-shoot-oidc-service
FROM gcr.io/distroless/static-debian11:nonroot AS gardener-extension-shoot-oidc-service
WORKDIR /

COPY --from=builder /go/bin/gardener-extension-shoot-oidc-service /gardener-extension-shoot-oidc-service
ENTRYPOINT ["/gardener-extension-shoot-oidc-service"]
