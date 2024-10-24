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

package server

import (
	"context"
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/helpers"
	"github.com/guacsec/guac/pkg/logging"
)

// searchVulnerabilitiesViaArtifact searches for vulnerabilities associated with the given digest.
//
// This function utilizes the function GetDepsForArtifact to traverse the dependencies
// of the specified digest. It then fetches and returns vulnerabilities for each discovered package.
//
// Parameters:
// - ctx: The context for the operation, used for cancellation and deadlines.
// - gqlClient: The GraphQL client used for querying the database.
// - artifactSpec: The specification of the digest from which to start the search.
// - includeDependencies: A boolean flag indicating whether to include software components in the search.
//
// Returns:
// - A slice of Vulnerability objects containing the found vulnerabilities.
// - An error, if any occurs during the search or data retrieval.
func searchVulnerabilitiesViaArtifact(ctx context.Context, gqlClient graphql.Client, artifact string) ([]gen.Vulnerability, error) {
	logger := logging.FromContext(ctx)
	var vulnerabilities []gen.Vulnerability

	pkgs, err := GetDepsForArtifact(ctx, gqlClient, artifact)
	if err != nil {
		return nil, err
	}

	for pkg := range pkgs {
		vulns, err := model.CertifyVuln(ctx, gqlClient, model.CertifyVulnSpec{
			Package: &model.PkgSpec{
				Id: &pkg,
			},
		})
		if err != nil {
			logger.Errorf("error fetching vulnerabilities from package spec: %v", err)
			return nil, helpers.Err502
		}

		for _, vuln := range vulns.CertifyVuln {
			vulnerability := gen.Vulnerability{
				Metadata: gen.ScanMetadata{
					Collector:      &vuln.Metadata.Collector,
					DbUri:          &vuln.Metadata.DbUri,
					DbVersion:      &vuln.Metadata.DbVersion,
					Origin:         &vuln.Metadata.Origin,
					ScannerUri:     &vuln.Metadata.ScannerUri,
					ScannerVersion: &vuln.Metadata.ScannerVersion,
					TimeScanned:    &vuln.Metadata.TimeScanned,
				},
				Vulnerability: gen.VulnerabilityDetails{
					Type: &vuln.Vulnerability.Type,
				},
			}

			vulnerability.Package = vuln.Package.Namespaces[0].Names[0].Versions[0].Purl

			for _, vIDs := range vuln.Vulnerability.VulnerabilityIDs {
				vulnerability.Vulnerability.VulnerabilityIDs = append(vulnerability.Vulnerability.VulnerabilityIDs, vIDs.VulnerabilityID)
			}

			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities, nil
}

// searchLicensesViaArtifact searches for licenses associated with the given artifact
// and its dependencies.
//
// Parameters:
// - ctx: The context for the operation
// - gqlClient: The GraphQL client used for querying
// - artifact: The artifact digest (e.g., "sha256:<digest>") to start the search from
//
// Returns:
// - A slice of Legal objects containing the found licenses
// - An error, if any occurs during the search or data retrieval
//
// The function utilizes GetDepsForArtifact to traverse the dependencies
// of the specified artifact and collects licenses for each discovered package.
func searchLicensesViaArtifact(ctx context.Context, gqlClient graphql.Client, artifact string) (gen.LicenseList, error) {
	logger := logging.FromContext(ctx)
	var licenses gen.LicenseList

	// GetDepsForArtifact returns a map of package IDs to package nodes
	pkgs, err := GetDepsForArtifact(ctx, gqlClient, artifact)
	if err != nil {
		return nil, err
	}

	for pkgID := range pkgs {
		certLegals, err := model.CertifyLegal(ctx, gqlClient, model.CertifyLegalSpec{
			Subject: &model.PackageOrSourceSpec{
				Package: &model.PkgSpec{
					Id: &pkgID,
				},
			},
		})
		if err != nil {
			logger.Errorf("error fetching licenses from package spec: %v", err)
			return nil, helpers.Err502
		}

		for _, lic := range certLegals.CertifyLegal {
			license := gen.Legal{
				Attribution:       &lic.Attribution,
				Collector:         &lic.Collector,
				DeclaredLicense:   &lic.DeclaredLicense,
				DiscoveredLicense: &lic.DiscoveredLicense,
				Justification:     &lic.Justification,
				Origin:            &lic.Origin,
				TimeScanned:       &lic.TimeScanned,
			}

			var declaredLicenses []gen.License
			var discoveredLicenses []gen.License

			for _, declared := range lic.DeclaredLicenses {
				declaredLicenses = append(declaredLicenses, gen.License{
					Inline:      declared.Inline,
					ListVersion: declared.ListVersion,
					Name:        &declared.Name,
				})
			}

			for _, discovered := range lic.DiscoveredLicenses {
				discoveredLicenses = append(discoveredLicenses, gen.License{
					Inline:      discovered.Inline,
					ListVersion: discovered.ListVersion,
					Name:        &discovered.Name,
				})
			}

			license.DeclaredLicenses = &declaredLicenses
			license.DiscoveredLicenses = &discoveredLicenses

			licenses = append(licenses, license)
		}
	}

	return licenses, nil
}
