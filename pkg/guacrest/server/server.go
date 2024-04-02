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
	"fmt"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/scorer"

	"github.com/Khan/genqlient/graphql"
	"github.com/guacsec/guac/pkg/dependencies"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
)

const (
	numberOfDependents = "numberOfDependents"
	scorecard          = "scorecard"
)

// DefaultServer implements the API, backed by the GraphQL Server
type DefaultServer struct {
	gqlClient graphql.Client
}

func NewDefaultServer(gqlClient graphql.Client) *DefaultServer {
	return &DefaultServer{gqlClient: gqlClient}
}

func (s *DefaultServer) HealthCheck(ctx context.Context, request gen.HealthCheckRequestObject) (gen.HealthCheckResponseObject, error) {
	return gen.HealthCheck200JSONResponse("Server is healthy"), nil
}

func (s *DefaultServer) ScoreNACD(ctx context.Context, request gen.ScoreNACDRequestObject) (gen.ScoreNACDResponseObject, error) {
	metricParams := make(map[string]scorer.ParameterValues)

	likelihoodParams := make(map[string][]scorer.ParameterValues)
	criticalityParams := make(map[string][]scorer.ParameterValues)

	scorecardValues := make(map[string]float64)
	numberOfDependentsValues := make(map[string]int)

	if request.Body == nil {
		// we know that the user didn't provide a JSON document, so we use our default document

		data, err := scorer.ReadNACDInputFile("pkg/scorer/defaultInput.json")

		if err != nil {
			fmt.Errorf("error reading default input file, %v", err)
		}

		metricParams[numberOfDependents] = data.Criticality.NumberOfDependents
		metricParams[scorecard] = data.Likelihood.Scorecard
	} else {
		// the user provided a JSON document

		if request.Body.Criticality.NumberOfDependents != nil {
			metricParams[numberOfDependents] = scorer.ParameterValues{
				Weight: float64(request.Body.Criticality.NumberOfDependents.Weight),
				K:      float64(request.Body.Criticality.NumberOfDependents.K),
				L:      float64(request.Body.Criticality.NumberOfDependents.L),
			}
		}

		if request.Body.Likelihood.Scorecard != nil {
			metricParams[scorecard] = scorer.ParameterValues{
				Weight: float64(request.Body.Likelihood.Scorecard.Weight),
				K:      float64(request.Body.Likelihood.Scorecard.K),
				L:      float64(request.Body.Likelihood.Scorecard.L),
			}
		}
	}

	for _, metric := range []string{numberOfDependents, scorecard} {
		if _, ok := metricParams[metric]; !ok {
			continue
		}

		p := scorer.ParameterValues{
			Weight: metricParams[metric].Weight,
			K:      metricParams[metric].K,
			L:      metricParams[metric].L,
		}

		if metric == "scorecard" {
			scores, err := model.Scorecards(ctx, s.gqlClient, model.CertifyScorecardSpec{})

			if err != nil {
				fmt.Println(err)
			}

			for _, scorecard := range scores.Scorecards {
				name := scorecard.Source.Type + "_" + scorecard.Source.Namespaces[0].Namespace + "_" + scorecard.Source.Namespaces[0].Names[0].Name

				p.Parameter = scorecard.Scorecard.AggregateScore
				likelihoodParams[name] = append(likelihoodParams[name], p)
				scorecardValues[name] = scorecard.Scorecard.AggregateScore
			}
		} else if metric == "numberOfDependents" {
			dependents, err := dependencies.GetDependenciesBySortedDependentCnt(ctx, s.gqlClient)

			if err != nil {
				fmt.Errorf("error getting dependencies: %v", err)
			}

			for _, pkg := range dependents {
				p.Parameter = float64(pkg.DependentCount)
				criticalityParams[pkg.Name] = append(criticalityParams[pkg.Name], p)
				numberOfDependentsValues[pkg.Name] = pkg.DependentCount
			}
		} else {
			fmt.Errorf("unknown metric")
		}
	}

	packages, err := model.Packages(ctx, s.gqlClient, model.PkgSpec{})
	if err != nil {
		return nil, fmt.Errorf("failed to get packages: %v", err)
	}

	result := gen.ScoreNACD200JSONResponse{}

	for _, p := range packages.Packages {
		name := p.Type + "_" + p.Namespaces[0].Namespace + "_" + p.Namespaces[0].Names[0].Name

		criticality := scorer.Scorer(criticalityParams[name])
		likelihood := scorer.Scorer(likelihoodParams[name])

		risk, err := scorer.RiskCalculator(criticality, likelihood, float64(request.Body.CriticalityWeight), float64(request.Body.LikelihoodWeight))

		if err != nil {
			fmt.Errorf("failed to calculate risk: %v", err)
		}

		riskResponse := float32(*risk)
		criticalityResponse := float32(criticality)
		likelihoodResponse := float32(likelihood)
		numDependentsResponse := numberOfDependentsValues[name]
		scorecardResponse := float32(scorecardValues[name])

		resp := gen.NACDScoreResponse{
			{
				PkgName:          &name,
				RiskScore:        &riskResponse,
				CriticalityScore: &criticalityResponse,
				LikelihoodScore:  &likelihoodResponse,
				Metrics: &struct {
					NumberOfDependents *int     `json:"numberOfDependents,omitempty"`
					ScorecardScore     *float32 `json:"scorecardScore,omitempty"`
				}{
					NumberOfDependents: &numDependentsResponse,
					ScorecardScore:     &scorecardResponse,
				},
			},
		}

		result = append(result, resp...)
	}

	return result, nil
}

func (s *DefaultServer) AnalyzeDependencies(ctx context.Context, request gen.AnalyzeDependenciesRequestObject) (gen.AnalyzeDependenciesResponseObject, error) {
	switch request.Params.Sort {
	case gen.Frequency:
		packages, err := dependencies.GetDependenciesBySortedDependentCnt(ctx, s.gqlClient)
		if err != nil {
			return gen.AnalyzeDependencies500JSONResponse{
				InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
					Message: err.Error(),
				},
			}, nil
		}

		var packageNames []gen.PackageName

		for _, p := range packages {
			pac := p // have to do this because we don't want packageNames to keep on appending a pointer of the same variable p.
			packageNames = append(packageNames, gen.PackageName{
				Name:           pac.Name,
				DependentCount: pac.DependentCount,
			})
		}

		val := gen.AnalyzeDependencies200JSONResponse{
			PackageNameListJSONResponse: packageNames,
		}

		return val, nil
	case gen.Scorecard:
		return nil, fmt.Errorf("scorecard sort is unimplemented")
	default:
		return nil, fmt.Errorf("%v sort is unsupported", request.Params.Sort)
	}
}

func (s *DefaultServer) RetrieveDependencies(ctx context.Context, request gen.RetrieveDependenciesRequestObject) (gen.RetrieveDependenciesResponseObject, error) {
	return nil, fmt.Errorf("Unimplemented")
}
