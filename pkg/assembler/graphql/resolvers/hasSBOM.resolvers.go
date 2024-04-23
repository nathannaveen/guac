package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.44

import (
	"context"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// IngestHasSbom is the resolver for the ingestHasSBOM field.
func (r *mutationResolver) IngestHasSbom(ctx context.Context, subject model.PackageOrArtifactInput, hasSbom model.HasSBOMInputSpec, includes model.HasSBOMIncludesInputSpec) (string, error) {
	funcName := "IngestHasSbom"
	if err := validatePackageOrArtifactInput(&subject, funcName); err != nil {
		return "", gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	if hasSbom.KnownSince.IsZero() {
		return "", gqlerror.Errorf("hasSbom.KnownSince is a zero time")
	}

	return r.Backend.IngestHasSbom(ctx, subject, hasSbom, includes)
}

// IngestHasSBOMs is the resolver for the ingestHasSBOMs field.
func (r *mutationResolver) IngestHasSBOMs(ctx context.Context, subjects model.PackageOrArtifactInputs, hasSBOMs []*model.HasSBOMInputSpec, includes []*model.HasSBOMIncludesInputSpec) ([]string, error) {
	funcName := "IngestHasSBOMs"
	valuesDefined := 0
	ingestedHasSBOMSIDS := []string{}
	if len(subjects.Packages) > 0 {
		if len(subjects.Packages) != len(hasSBOMs) {
			return ingestedHasSBOMSIDS, gqlerror.Errorf("%v :: uneven packages and hasSBOMs for ingestion", funcName)
		}
		valuesDefined = valuesDefined + 1
	}
	if len(subjects.Artifacts) > 0 {
		if len(subjects.Artifacts) != len(hasSBOMs) {
			return ingestedHasSBOMSIDS, gqlerror.Errorf("%v :: uneven artifact and hasSBOMs for ingestion", funcName)
		}
		valuesDefined = valuesDefined + 1
	}
	if valuesDefined != 1 {
		return ingestedHasSBOMSIDS, gqlerror.Errorf("%v :: must specify at most packages or artifacts for ingestion", funcName)
	}

	for _, hasSbom := range hasSBOMs {
		if hasSbom.KnownSince.IsZero() {
			return ingestedHasSBOMSIDS, gqlerror.Errorf("hasSBOMS contains a zero time")
		}
	}

	if len(hasSBOMs) != len(includes) {
		return ingestedHasSBOMSIDS, gqlerror.Errorf("%v :: uneven hasSBOMs and includes for ingestion", funcName)
	}
	return r.Backend.IngestHasSBOMs(ctx, subjects, hasSBOMs, includes)
}

// HasSbom is the resolver for the HasSBOM field.
func (r *queryResolver) HasSbom(ctx context.Context, hasSBOMSpec model.HasSBOMSpec) ([]*model.HasSbom, error) {
	if err := validatePackageOrArtifactQueryFilter(hasSBOMSpec.Subject); err != nil {
		return nil, gqlerror.Errorf("%v :: %s", "HasSBOM", err)
	}
	return r.Backend.HasSBOM(ctx, &hasSBOMSpec)
}

// HasSBOMList is the resolver for the HasSBOMList field.
func (r *queryResolver) HasSBOMList(ctx context.Context, hasSBOMSpec model.HasSBOMSpec, after *string, first *int) (*model.HasSBOMConnection, error) {
	if err := validatePackageOrArtifactQueryFilter(hasSBOMSpec.Subject); err != nil {
		return nil, gqlerror.Errorf("%v :: %s", "HasSBOM", err)
	}
	return r.Backend.HasSBOMList(ctx, hasSBOMSpec, after, first)
}
