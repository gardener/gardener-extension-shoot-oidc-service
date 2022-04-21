# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# builder
FROM golang:1.17.9 AS builder

WORKDIR /go/src/github.com/gardener/gardener-extension-shoot-oidc-service
COPY . .
RUN make install

############# gardener-extension-shoot-oidc-service
FROM alpine:3.15.4 AS gardener-extension-shoot-oidc-service

COPY charts /charts
COPY --from=builder /go/bin/gardener-extension-shoot-oidc-service /gardener-extension-shoot-oidc-service
ENTRYPOINT ["/gardener-extension-shoot-oidc-service"]
