// SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package suites

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/gardener/gardener/test/framework"
	"github.com/gardener/gardener/test/framework/config"
	"github.com/gardener/gardener/test/framework/reporter"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	_ "github.com/gardener/gardener-extension-shoot-oidc-service/test/integration/healthcheck"
)

// go test -timeout 1200s ./test/integration/suites/run_suite_test.go --kubecfg=PATH --project-namespace=PROJ-NAMESPACE --shoot-name=SHOOT_NAME
var (
	configFilePath = flag.String("config", "", "Specify the configuration file")
	esIndex        = flag.String("es-index", "gardener-testsuite", "Specify the elastic search index where the report should be ingested")
	reportFilePath = flag.String("report-file", "/tmp/shoot_res.json", "Specify the file to write the test results")
)

func TestMain(m *testing.M) {
	framework.RegisterShootFrameworkFlags()
	flag.Parse()

	if err := config.ParseConfigForFlags(*configFilePath, flag.CommandLine); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	RegisterFailHandler(Fail)

	AfterSuite(func() {
		framework.CommonAfterSuite()
	})

	os.Exit(m.Run())
}

func TestGardenerSuite(t *testing.T) {
	RunSpecs(t, "Shoot-oidc-service Test Suite")
}

var _ = ReportAfterSuite("Report to Elasticsearch", func(report Report) {
	reporter.ReportResults(*reportFilePath, *esIndex, report)
})
