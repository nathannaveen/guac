package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.44

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// IngestCertifyLegal is the resolver for the ingestCertifyLegal field.
func (r *mutationResolver) IngestCertifyLegal(ctx context.Context, subject model.PackageOrSourceInput, declaredLicenses []*model.IDorLicenseInput, discoveredLicenses []*model.IDorLicenseInput, certifyLegal model.CertifyLegalInputSpec) (string, error) {
	funcName := "IngestCertifyLegal"
	if err := validatePackageOrSourceInput(&subject, funcName); err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}

	return r.Backend.IngestCertifyLegal(ctx, subject, declaredLicenses, discoveredLicenses, &certifyLegal)
}

// IngestCertifyLegals is the resolver for the ingestCertifyLegals field.
func (r *mutationResolver) IngestCertifyLegals(ctx context.Context, subjects model.PackageOrSourceInputs, declaredLicensesList [][]*model.IDorLicenseInput, discoveredLicensesList [][]*model.IDorLicenseInput, certifyLegals []*model.CertifyLegalInputSpec) ([]string, error) {
	funcName := "IngestCertifyLegals"
	valuesDefined := 0
	if (len(certifyLegals) != len(discoveredLicensesList)) ||
		(len(certifyLegals) != len(declaredLicensesList)) {
		return nil, gqlerror.Errorf("%v :: must specify equal length license lists and certifyLegals", funcName)
	}
	if len(subjects.Packages) > 0 {
		if len(subjects.Packages) != len(certifyLegals) {
			return nil, gqlerror.Errorf("%v :: uneven packages for ingestion", funcName)
		}
		valuesDefined = valuesDefined + 1
	}
	if len(subjects.Sources) > 0 {
		if len(subjects.Sources) != len(certifyLegals) {
			return nil, gqlerror.Errorf("%v :: uneven sources for ingestion", funcName)
		}
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined != 1 {
		return nil, gqlerror.Errorf("%v :: must specify at most packages or sources", funcName)
	}
	return r.Backend.IngestCertifyLegals(ctx, subjects, declaredLicensesList, discoveredLicensesList, certifyLegals)
}

// CertifyLegal is the resolver for the CertifyLegal field.
func (r *queryResolver) CertifyLegal(ctx context.Context, certifyLegalSpec model.CertifyLegalSpec) ([]*model.CertifyLegal, error) {
	if err := validatePackageOrSourceQueryFilter(certifyLegalSpec.Subject); err != nil {
		return nil, gqlerror.Errorf("CertifyLegal :: %v", err)
	}

	return r.Backend.CertifyLegal(ctx, &certifyLegalSpec)
}

// CertifyLegalList is the resolver for the CertifyLegalList field.
func (r *queryResolver) CertifyLegalList(ctx context.Context, certifyLegalSpec model.CertifyLegalSpec, after *string, first *int) (*model.CertifyLegalConnection, error) {
	if err := validatePackageOrSourceQueryFilter(certifyLegalSpec.Subject); err != nil {
		return nil, gqlerror.Errorf("CertifyLegal :: %v", err)
	}

	return r.Backend.CertifyLegalList(ctx, certifyLegalSpec, after, first)
}
