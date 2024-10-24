//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

package server

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	clients "github.com/guacsec/guac/internal/testing/graphqlClients"
	"github.com/guacsec/guac/internal/testing/ptrfrom"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/logging"
)

func TestSearchVulnerabilitiesViaPkg(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name                string
		data                clients.GuacData
		purl                string
		includeDependencies bool
		startSBOM           model.AllHasSBOMTree
		expected            []gen.Vulnerability
	}{
		{
			name: "Basic vulnerability retrieval",
			data: clients.GuacData{
				Packages: []string{
					"pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
				},
				Vulnerabilities: []string{
					"osv/osv-2022-0001",
				},
				CertifyVulns: []clients.CertifyVuln{
					{
						Package:       "pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
						Vulnerability: "osv/osv-2022-0001",
						Metadata: &model.ScanMetadataInput{
							TimeScanned:    time.Now(),
							DbUri:          "https://vuln-db.example.com",
							DbVersion:      "1.0.0",
							ScannerUri:     "test-scanner",
							ScannerVersion: "1.0.0",
							Origin:         "test-origin",
							Collector:      "test-collector",
						},
					},
				},
			},
			purl:                "pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
			includeDependencies: false,
			startSBOM:           model.AllHasSBOMTree{},
			expected: []gen.Vulnerability{
				{
					Metadata: gen.ScanMetadata{
						TimeScanned:    ptrfrom.Time(time.Now()),
						DbUri:          ptrfrom.String("https://vuln-db.example.com"),
						DbVersion:      ptrfrom.String("1.0.0"),
						ScannerUri:     ptrfrom.String("test-scanner"),
						ScannerVersion: ptrfrom.String("1.0.0"),
						Origin:         ptrfrom.String("test-origin"),
						Collector:      ptrfrom.String("test-collector"),
					},
					Vulnerability: gen.VulnerabilityDetails{
						Type:             ptrfrom.String("osv"),
						VulnerabilityIDs: []string{"osv-2022-0001"},
					},
					Package: "pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gqlClient := clients.SetupTest(t)
			clients.Ingest(ctx, t, gqlClient, test.data)

			escapedPurl := url.QueryEscape(test.purl)

			vulnerabilities, err := searchVulnerabilitiesViaPkg(ctx, gqlClient, escapedPurl, &test.includeDependencies)
			if err != nil {
				t.Fatalf("searchVulnerabilitiesViaPkg returned unexpected error: %v", err)
			}

			if diff := cmp.Diff(test.expected, vulnerabilities, cmpopts.EquateApproxTime(time.Second)); diff != "" {
				t.Errorf("searchVulnerabilitiesViaPkg mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSearchLicensesViaPkg(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	tests := []struct {
		name                string
		data                clients.GuacData
		purl                string
		includeDependencies bool
		expected            gen.LicenseList
	}{
		{
			name: "Basic license retrieval",
			data: clients.GuacData{
				Packages: []string{
					"pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
				},
				Licenses: []clients.License{
					{
						Name:        "MIT",
						ListVersion: "test-ListVersion",
					},
					{
						Name:        "Apache-2.0",
						ListVersion: "test-ListVersion2",
					},
				},
				CertifyLegals: []clients.CertifyLegal{
					{
						Subject: "pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
						Legal: &model.CertifyLegalInputSpec{
							DeclaredLicense:   "MIT",
							DiscoveredLicense: "Apache-2.0",
							Justification:     "test justification",
							TimeScanned:       time.Now(),
							Origin:            "test-origin",
							Collector:         "test-collector",
						},
						DeclaredLicenses:   []string{"MIT"},
						DiscoveredLicenses: []string{"Apache-2.0"},
					},
				},
			},
			purl:                "pkg:golang/github.com/hashicorp/consul/sdk@v1.0.0",
			includeDependencies: false,
			expected: gen.LicenseList{
				{
					Attribution:       ptrfrom.String(""),
					Collector:         ptrfrom.String("test-collector"),
					DeclaredLicense:   ptrfrom.String("MIT"),
					DiscoveredLicense: ptrfrom.String("Apache-2.0"),
					Justification:     ptrfrom.String("test justification"),
					Origin:            ptrfrom.String("test-origin"),
					TimeScanned:       ptrfrom.Time(time.Now()),
					DeclaredLicenses: &[]gen.License{
						{
							Name:        ptrfrom.String("MIT"),
							ListVersion: ptrfrom.String("test-ListVersion"),
						},
					},
					DiscoveredLicenses: &[]gen.License{
						{
							Name:        ptrfrom.String("Apache-2.0"),
							ListVersion: ptrfrom.String("test-ListVersion2"),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gqlClient := clients.SetupTest(t)
			clients.Ingest(ctx, t, gqlClient, test.data)

			escapedPurl := url.QueryEscape(test.purl)

			licenses, err := searchLicensesViaPkg(ctx, gqlClient, escapedPurl, &test.includeDependencies)
			if err != nil {
				t.Fatalf("searchLicensesViaPkg returned unexpected error: %v", err)
			}

			if diff := cmp.Diff(test.expected, licenses, cmpopts.EquateApproxTime(time.Second)); diff != "" {
				t.Errorf("searchLicensesViaPkg mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
