//
// Copyright 2022 The GUAC Authors.
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

package osv

import (
	"context"
	"errors"
	"fmt"
	"github.com/guacsec/guac/pkg/clients"
	"net/http"
	"strings"
	"time"

	osv_scanner "github.com/google/osv-scanner/pkg/osv"
	"github.com/guacsec/guac/pkg/certifier"
	attestation_vuln "github.com/guacsec/guac/pkg/certifier/attestation"
	"github.com/guacsec/guac/pkg/certifier/components/root_package"
	"github.com/guacsec/guac/pkg/events"
	"github.com/guacsec/guac/pkg/handler/processor"
	attestationv1 "github.com/in-toto/attestation/go/v1"
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	URI          string = "osv.dev"
	VERSION      string = "0.0.14"
	INVOC_URI    string = "guac"
	PRODUCER_ID  string = "guacsec/guac"
	OSVCollector string = "osv_certifier"
)

var ErrOSVComponenetTypeMismatch error = errors.New("rootComponent type is not []*root_package.PackageNode")

type osvCertifier struct {
	osvHTTPClient *http.Client
}

// NewOSVCertificationParser initializes the OSVCertifier
func NewOSVCertificationParser() certifier.Certifier {
	return &osvCertifier{
		osvHTTPClient: clients.NewOsvDevClient(context.Background()),
	}
}

// CertifyComponent takes in the root component from the gauc database and does a recursive scan
// to generate vulnerability attestations
func (o *osvCertifier) CertifyComponent(ctx context.Context, rootComponent interface{}, docChannel chan<- *processor.Document) error {
	packageNodes, ok := rootComponent.([]*root_package.PackageNode)
	if !ok {
		return ErrOSVComponenetTypeMismatch
	}

	var query osv_scanner.BatchedQuery
	packMap := map[string][]*root_package.PackageNode{}
	for _, node := range packageNodes {
		// skip any purls that are generated by GUAC as they will not be found in OSV
		if strings.Contains(node.Purl, "pkg:guac") {
			continue
		}
		if _, ok := packMap[node.Purl]; !ok {
			purlQuery := osv_scanner.MakePURLRequest(node.Purl)
			query.Queries = append(query.Queries, purlQuery)
		}
		packMap[node.Purl] = append(packMap[node.Purl], node)
	}

	resp, err := osv_scanner.MakeRequestWithClient(query, o.osvHTTPClient)
	if err != nil {
		return fmt.Errorf("osv.dev batched request failed: %w", err)
	}
	for i, query := range query.Queries {
		response := resp.Results[i]
		purl := query.Package.PURL
		if err := generateDocument(packMap[purl], response.Vulns, docChannel); err != nil {
			return fmt.Errorf("could not generate document from OSV results: %w", err)
		}
	}
	return nil
}

func generateDocument(packNodes []*root_package.PackageNode, vulns []osv_scanner.MinimalVulnerability, docChannel chan<- *processor.Document) error {
	currentTime := time.Now()
	for _, node := range packNodes {
		payload, err := json.Marshal(CreateAttestation(node, vulns, currentTime))
		if err != nil {
			return fmt.Errorf("unable to marshal attestation: %w", err)
		}
		doc := &processor.Document{
			Blob:   payload,
			Type:   processor.DocumentITE6Vul,
			Format: processor.FormatJSON,
			SourceInformation: processor.SourceInformation{
				Collector:   OSVCollector,
				Source:      OSVCollector,
				DocumentRef: events.GetDocRef(payload),
			},
		}
		docChannel <- doc
	}
	return nil
}

func CreateAttestation(packageNode *root_package.PackageNode, vulns []osv_scanner.MinimalVulnerability, currentTime time.Time) *attestation_vuln.VulnerabilityStatement {
	attestation := &attestation_vuln.VulnerabilityStatement{
		Statement: attestationv1.Statement{
			Type:          attestationv1.StatementTypeUri,
			PredicateType: attestation_vuln.PredicateVuln,
		},
		Predicate: attestation_vuln.VulnerabilityPredicate{
			Invocation: attestation_vuln.Invocation{
				Uri:        INVOC_URI,
				ProducerID: PRODUCER_ID,
			},
			Scanner: attestation_vuln.Scanner{
				Uri:     URI,
				Version: VERSION,
			},
			Metadata: attestation_vuln.Metadata{
				ScannedOn: &currentTime,
			},
		},
	}

	subject := &attestationv1.ResourceDescriptor{Uri: packageNode.Purl}
	attestation.Statement.Subject = append(attestation.Statement.Subject, subject)

	for _, vuln := range vulns {
		attestation.Predicate.Scanner.Result = append(attestation.Predicate.Scanner.Result, attestation_vuln.Result{
			VulnerabilityId: vuln.ID,
		})
	}
	return attestation
}
