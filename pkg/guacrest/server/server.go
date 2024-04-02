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
	"github.com/Khan/genqlient/graphql"
	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/dependencies"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"github.com/guacsec/guac/pkg/scorer"
	"math"
	"time"
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

	startTime := time.Now()

	fmt.Printf("got input at: %v\n", time.Since(startTime))

	if request.Body == nil {
		// we know that the user didn't provide a JSON document, so we use our default document

		data, err := scorer.ReadNACDInputFile("pkg/scorer/defaultInput.json")

		if err != nil {
			return gen.ScoreNACD500JSONResponse{
				InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
					Message: fmt.Sprintf("error reading input file: %v", err.Error()),
				},
			}, nil
		}

		metricParams[numberOfDependents] = data.Criticality.NumberOfDependents
		metricParams[scorecard] = data.Likelihood.Scorecard
	} else {
		// the user provided a JSON document

		if request.Body.Criticality.NumberOfDependents != nil {
			metricParams[numberOfDependents] = scorer.ParameterValues{
				Weight: float64(request.Body.Criticality.NumberOfDependents.Weight),
				K:      float64(request.Body.Criticality.NumberOfDependents.KValue),
				L:      float64(request.Body.Criticality.NumberOfDependents.LValue),
			}
		} else {
			return gen.ScoreNACD500JSONResponse{
				InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
					Message: fmt.Sprintf("number of dependents body is empty"),
				},
			}, nil
		}

		if request.Body.Likelihood.Scorecard != nil {
			metricParams[scorecard] = scorer.ParameterValues{
				Weight: float64(request.Body.Likelihood.Scorecard.Weight),
				K:      float64(request.Body.Likelihood.Scorecard.KValue),
				L:      float64(request.Body.Likelihood.Scorecard.LValue),
			}
		} else {
			return gen.ScoreNACD500JSONResponse{
				InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
					Message: fmt.Sprintf("scorecard body is empty"),
				},
			}, nil
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
				return gen.ScoreNACD500JSONResponse{
					InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
						Message: fmt.Sprintf("error getting s scores: %v", err.Error()),
					},
				}, nil
			}

			for _, s := range scores.Scorecards {
				name := s.Source.Type + "_" + s.Source.Namespaces[0].Namespace + "_" + s.Source.Namespaces[0].Names[0].Name

				p2 := scorer.ParameterValues{
					Weight: metricParams[metric].Weight,
					K:      metricParams[metric].K,
					L:      metricParams[metric].L,
				}

				p2.Parameter = s.Scorecard.AggregateScore
				likelihoodParams[name] = append(likelihoodParams[name], p2)
				scorecardValues[name] = s.Scorecard.AggregateScore
				fmt.Println("scorecard score: ", s.Scorecard.AggregateScore)
			}

			fmt.Println("total scorecard scores:", scorecardValues)

		} else if metric == "numberOfDependents" {
			dependents, err := dependencies.GetDependenciesBySortedDependentCnt(ctx, s.gqlClient)

			fmt.Println("len dependents: ", len(dependents))

			if err != nil {
				return gen.ScoreNACD500JSONResponse{
					InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
						Message: fmt.Sprintf("error getting dependencies: %v", err.Error()),
					},
				}, nil
			}

			for _, pkg := range dependents {
				p.Parameter = float64(pkg.DependentCount)
				criticalityParams[pkg.Name] = append(criticalityParams[pkg.Name], p)
				numberOfDependentsValues[pkg.Name] = pkg.DependentCount
			}
		} else {
			return gen.ScoreNACD400JSONResponse{
				BadRequestJSONResponse: gen.BadRequestJSONResponse{
					Message: fmt.Sprintf("unknown metric"),
				},
			}, nil
		}
	}

	result := gen.ScoreNACD200JSONResponse{}

	sboms, err := model.HasSBOMs(ctx, s.gqlClient, model.HasSBOMSpec{})

	fmt.Println(len(sboms.HasSBOM))

	if err != nil {
		return nil, fmt.Errorf("error getting dependencies: %v", err)
	}

	for _, resp := range sboms.HasSBOM {
		// Skip entries from "deps.dev" because they are inconsistent.
		if resp.Origin == deps_dev.DepsCollector {
			continue
		}
		// Iterate through the included dependencies of each SBOM.
		for _, dependency := range resp.IncludedDependencies {
			// TODO: Make the names actually unique, not just add "_".
			name := dependency.Package.Type + "_" + dependency.Package.Namespaces[0].Namespace + "_" + dependency.Package.Namespaces[0].Names[0].Name

			//fmt.Println("name:", name)

			criticality, err := scorer.Scorer(criticalityParams[name])

			if err != nil {
				return gen.ScoreNACD500JSONResponse{
					InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
						Message: fmt.Sprintf("error scoring criticality: %v", err.Error()),
					},
				}, nil
			}

			likelihood, err := scorer.Scorer(likelihoodParams[name])

			if err != nil {
				return gen.ScoreNACD500JSONResponse{
					InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
						Message: fmt.Sprintf("error scoring liklihood: %v", err.Error()),
					},
				}, nil
			}

			risk, err := scorer.RiskCalculator(*criticality, *likelihood, float64(request.Body.CriticalityWeight), float64(request.Body.LikelihoodWeight))

			if err != nil {
				return gen.ScoreNACD500JSONResponse{
					InternalServerErrorJSONResponse: gen.InternalServerErrorJSONResponse{
						Message: fmt.Sprintf("error calculating risk: %v", err.Error()),
					},
				}, nil
			}

			resp := gen.NACDScoreResponse{
				{
					PkgName: &name,
					Metrics: &struct {
						NumberOfDependents *int     `json:"number_of_dependents"`
						ScorecardScore     *float32 `json:"scorecard_score"`
					}{},
				},
			}

			if !math.IsNaN(*risk) {
				riskResponse := float32(*risk)
				resp[0].RiskScore = &riskResponse
			}
			if !math.IsNaN(*likelihood) {
				likelihoodResponse := float32(*likelihood)
				resp[0].LikelihoodScore = &likelihoodResponse
			}
			if !math.IsNaN(*criticality) {
				criticalityResponse := float32(*criticality)
				resp[0].CriticalityScore = &criticalityResponse
			}
			if _, ok := numberOfDependentsValues[name]; ok {
				numDependentsResponse := numberOfDependentsValues[name]
				resp[0].Metrics.NumberOfDependents = &numDependentsResponse
			}
			if _, ok := scorecardValues[name]; ok {
				scorecardResponse := float32(scorecardValues[name])
				resp[0].Metrics.ScorecardScore = &scorecardResponse
			}

			if !math.IsNaN(*likelihood) || scorecardValues[name] != 0 {
				result = append(result, resp...)
			}
		}
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
