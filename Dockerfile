# SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

############# builder
FROM --platform=$BUILDPLATFORM golang:1.26.0 AS builder

WORKDIR /go/src/github.com/gardener/gardener-extension-shoot-oidc-service

# Copy go mod and sum files
COPY go.mod go.sum ./
# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG EFFECTIVE_VERSION
RUN make build EFFECTIVE_VERSION=$EFFECTIVE_VERSION GOOS=$TARGETOS GOARCH=$TARGETARCH BUILD_OUTPUT_FILE="/output/bin/"

############# gardener-extension-shoot-oidc-service
FROM gcr.io/distroless/static-debian13:nonroot AS gardener-extension-shoot-oidc-service
WORKDIR /

COPY --from=builder /output/bin/gardener-extension-shoot-oidc-service /gardener-extension-shoot-oidc-service
ENTRYPOINT ["/gardener-extension-shoot-oidc-service"]
