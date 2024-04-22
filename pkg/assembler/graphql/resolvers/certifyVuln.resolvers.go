package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.44

import (
	"context"
	"fmt"
	"strings"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// IngestCertifyVuln is the resolver for the ingestCertifyVuln field.
func (r *mutationResolver) IngestCertifyVuln(ctx context.Context, pkg model.IDorPkgInput, vulnerability model.IDorVulnerabilityInput, certifyVuln model.ScanMetadataInput) (string, error) {
	// vulnerability input (type and vulnerability ID) will be enforced to be lowercase
	if vulnerability.VulnerabilityInput != nil {
		funcName := "IngestCertifyVuln"
		err := validateVulnerabilityIDInputSpec(*vulnerability.VulnerabilityInput)
		if err != nil {
			return "", gqlerror.Errorf("%v ::  %s", funcName, err)
		}
		return r.Backend.IngestCertifyVuln(ctx, pkg, model.IDorVulnerabilityInput{
			VulnerabilityTypeID: vulnerability.VulnerabilityTypeID,
			VulnerabilityNodeID: vulnerability.VulnerabilityNodeID,
			VulnerabilityInput:  &model.VulnerabilityInputSpec{Type: strings.ToLower(vulnerability.VulnerabilityInput.Type), VulnerabilityID: strings.ToLower(vulnerability.VulnerabilityInput.VulnerabilityID)},
		}, certifyVuln)
	} else {
		return r.Backend.IngestCertifyVuln(ctx, pkg, vulnerability, certifyVuln)
	}
}

// IngestCertifyVulns is the resolver for the ingestCertifyVulns field.
func (r *mutationResolver) IngestCertifyVulns(ctx context.Context, pkgs []*model.IDorPkgInput, vulnerabilities []*model.IDorVulnerabilityInput, certifyVulns []*model.ScanMetadataInput) ([]string, error) {
	funcName := "IngestCertifyVulns"
	ingestedCertifyVulnsIDS := []string{}
	if len(pkgs) != len(vulnerabilities) {
		return ingestedCertifyVulnsIDS, gqlerror.Errorf("%v :: uneven packages and vulnerabilities for ingestion", funcName)
	}
	if len(pkgs) != len(certifyVulns) {
		return ingestedCertifyVulnsIDS, gqlerror.Errorf("%v :: uneven packages and certifyVuln for ingestion", funcName)
	}

	// vulnerability input (type and vulnerability ID) will be enforced to be lowercase
	var lowercaseVulnList []*model.IDorVulnerabilityInput
	for _, v := range vulnerabilities {
		if v.VulnerabilityInput == nil {
			lowercaseVulnList = append(lowercaseVulnList, v)
			continue
		}
		err := validateVulnerabilityIDInputSpec(*v.VulnerabilityInput)
		if err != nil {
			return []string{}, gqlerror.Errorf("%v ::  %s", funcName, err)
		}

		lowercaseVulnInput := model.VulnerabilityInputSpec{
			Type:            strings.ToLower(v.VulnerabilityInput.Type),
			VulnerabilityID: strings.ToLower(v.VulnerabilityInput.VulnerabilityID),
		}

		lowercaseVulnList = append(lowercaseVulnList, &model.IDorVulnerabilityInput{
			VulnerabilityTypeID: v.VulnerabilityTypeID,
			VulnerabilityNodeID: v.VulnerabilityNodeID,
			VulnerabilityInput:  &lowercaseVulnInput,
		})
	}
	return r.Backend.IngestCertifyVulns(ctx, pkgs, lowercaseVulnList, certifyVulns)
}

// CertifyVuln is the resolver for the CertifyVuln field.
func (r *queryResolver) CertifyVuln(ctx context.Context, certifyVulnSpec model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	// vulnerability input (type and vulnerability ID) will be enforced to be lowercase

	if certifyVulnSpec.Vulnerability != nil {

		var typeLowerCase *string = nil
		var vulnIDLowerCase *string = nil
		if certifyVulnSpec.Vulnerability.Type != nil {
			lower := strings.ToLower(*certifyVulnSpec.Vulnerability.Type)
			typeLowerCase = &lower
		}
		if certifyVulnSpec.Vulnerability.VulnerabilityID != nil {
			lower := strings.ToLower(*certifyVulnSpec.Vulnerability.VulnerabilityID)
			vulnIDLowerCase = &lower
		}

		if certifyVulnSpec.Vulnerability.NoVuln != nil && !*certifyVulnSpec.Vulnerability.NoVuln {
			if certifyVulnSpec.Vulnerability.Type != nil && *typeLowerCase == "novuln" {
				return []*model.CertifyVuln{}, gqlerror.Errorf("novuln boolean set to false, cannot specify vulnerability type to be novuln")
			}
		}

		lowercaseVulnFilter := model.VulnerabilitySpec{
			ID:              certifyVulnSpec.Vulnerability.ID,
			Type:            typeLowerCase,
			VulnerabilityID: vulnIDLowerCase,
			NoVuln:          certifyVulnSpec.Vulnerability.NoVuln,
		}

		lowercaseCertifyVulnFilter := model.CertifyVulnSpec{
			ID:             certifyVulnSpec.ID,
			Package:        certifyVulnSpec.Package,
			Vulnerability:  &lowercaseVulnFilter,
			TimeScanned:    certifyVulnSpec.TimeScanned,
			DbURI:          certifyVulnSpec.DbURI,
			DbVersion:      certifyVulnSpec.DbVersion,
			ScannerURI:     certifyVulnSpec.ScannerURI,
			ScannerVersion: certifyVulnSpec.ScannerVersion,
			Origin:         certifyVulnSpec.Origin,
			Collector:      certifyVulnSpec.Collector,
		}
		return r.Backend.CertifyVuln(ctx, &lowercaseCertifyVulnFilter)
	} else {
		return r.Backend.CertifyVuln(ctx, &certifyVulnSpec)
	}
}

// CertifyVulnList is the resolver for the CertifyVulnList field.
func (r *queryResolver) CertifyVulnList(ctx context.Context, certifyVulnSpec model.CertifyVulnSpec, after *string, first *int) (*model.CertifyVulnConnection, error) {
	panic(fmt.Errorf("not implemented: CertifyVulnList - CertifyVulnList"))
}
