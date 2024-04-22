package resolvers

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.44

import (
	"context"
	"fmt"

	"github.com/guacsec/guac/pkg/assembler/graphql/model"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// IngestSlsa is the resolver for the ingestSLSA field.
func (r *mutationResolver) IngestSlsa(ctx context.Context, subject model.IDorArtifactInput, builtFrom []*model.IDorArtifactInput, builtBy model.IDorBuilderInput, slsa model.SLSAInputSpec) (string, error) {
	if len(builtFrom) < 1 {
		return "", gqlerror.Errorf("IngestSLSA :: Must have at least 1 builtFrom")
	}

	return r.Backend.IngestSLSA(ctx, subject, builtFrom, builtBy, slsa)
}

// IngestSLSAs is the resolver for the ingestSLSAs field.
func (r *mutationResolver) IngestSLSAs(ctx context.Context, subjects []*model.IDorArtifactInput, builtFromList [][]*model.IDorArtifactInput, builtByList []*model.IDorBuilderInput, slsaList []*model.SLSAInputSpec) ([]string, error) {
	funcName := "IngestSLSAs"
	ingestedSLSAIDS := []string{}
	if len(subjects) != len(slsaList) {
		return ingestedSLSAIDS, gqlerror.Errorf("%v :: uneven subjects and slsa attestation for ingestion", funcName)
	}
	if len(subjects) != len(builtFromList) {
		return ingestedSLSAIDS, gqlerror.Errorf("%v :: uneven subjects and built from artifact list for ingestion", funcName)
	}
	if len(subjects) != len(builtByList) {
		return ingestedSLSAIDS, gqlerror.Errorf("%v :: uneven subjects and built by for ingestion", funcName)
	}

	return r.Backend.IngestSLSAs(ctx, subjects, builtFromList, builtByList, slsaList)
}

// HasSlsa is the resolver for the HasSLSA field.
func (r *queryResolver) HasSlsa(ctx context.Context, hasSLSASpec model.HasSLSASpec) ([]*model.HasSlsa, error) {
	return r.Backend.HasSlsa(ctx, &hasSLSASpec)
}

// HasSLSAList is the resolver for the HasSLSAList field.
func (r *queryResolver) HasSLSAList(ctx context.Context, hasSLSASpec model.HasSLSASpec, after *string, first *int) (*model.HasSLSAConnection, error) {
	panic(fmt.Errorf("not implemented: HasSLSAList - HasSLSAList"))
}
