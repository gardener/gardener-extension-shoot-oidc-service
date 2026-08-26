// SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package kapiserver

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestKapiserver(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Kapiserver Webhook Suite")
}
