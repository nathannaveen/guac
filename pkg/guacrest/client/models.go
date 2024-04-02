// Package client provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen/v2 version v2.1.0 DO NOT EDIT.
package client

// Defines values for AnalyzeDependenciesParamsSort.
const (
	Frequency AnalyzeDependenciesParamsSort = "frequency"
	Scorecard AnalyzeDependenciesParamsSort = "scorecard"
)

// Error defines model for Error.
type Error struct {
	Message string `json:"Message"`
}

// NACDScoreRequest defines model for NACDScoreRequest.
type NACDScoreRequest struct {
	Criticality struct {
		NumberOfDependents *struct {
			// KValue Coefficient for scaling the number of dependents.
			KValue float32 `json:"k_value"`

			// LValue Offset for the number of dependents.
			LValue float32 `json:"l_value"`

			// Weight Weight of the number of dependents in the overall criticality score.
			Weight float32 `json:"weight"`
		} `json:"number_of_dependents,omitempty"`
	} `json:"criticality"`

	// CriticalityWeight Weight of the criticality in the overall score.
	CriticalityWeight float32 `json:"criticality_weight"`
	Likelihood        struct {
		Scorecard *struct {
			// KValue Coefficient for scaling the scorecard score.
			KValue float32 `json:"k_value"`

			// LValue Offset for the scorecard score.
			LValue float32 `json:"l_value"`

			// Weight Weight of the scorecard score in the overall likelihood score.
			Weight float32 `json:"weight"`
		} `json:"scorecard,omitempty"`
	} `json:"likelihood"`

	// LikelihoodWeight Weight of the likelihood in the overall score.
	LikelihoodWeight float32 `json:"likelihood_weight"`
}

// NACDScoreResponse defines model for NACDScoreResponse.
type NACDScoreResponse = []struct {
	// CriticalityScore The criticality of a package.
	CriticalityScore *float32 `json:"criticality_score"`

	// LikelihoodScore The likelihood of a package getting a vulnerability.
	LikelihoodScore *float32 `json:"likelihood_score"`

	// Metrics Detailed metrics analysis.
	Metrics *struct {
		// NumberOfDependents Number of packages that depend on this package.
		NumberOfDependents *int `json:"number_of_dependents"`

		// ScorecardScore The OpenSSF Scorecard score of this package.
		ScorecardScore *float32 `json:"scorecard_score"`
	} `json:"metrics,omitempty"`

	// PkgName Name of the package
	PkgName *string `json:"pkgName,omitempty"`

	// RiskScore The risk of a vulnerability of a package.
	RiskScore *float32 `json:"risk_score"`
}

// PackageName defines model for PackageName.
type PackageName struct {
	DependentCount int    `json:"DependentCount"`
	Name           string `json:"Name"`
}

// Purl defines model for Purl.
type Purl = string

// PaginationSpec defines model for PaginationSpec.
type PaginationSpec struct {
	Cursor   *string `json:"Cursor,omitempty"`
	PageSize *int    `json:"PageSize,omitempty"`
}

// BadGateway defines model for BadGateway.
type BadGateway = Error

// BadRequest defines model for BadRequest.
type BadRequest = Error

// InternalServerError defines model for InternalServerError.
type InternalServerError = Error

// PackageNameList defines model for PackageNameList.
type PackageNameList = []PackageName

// PurlList defines model for PurlList.
type PurlList = []Purl

// AnalyzeDependenciesParams defines parameters for AnalyzeDependencies.
type AnalyzeDependenciesParams struct {
	// PaginationSpec The pagination configuration for the query.
	//   * 'PageSize' specifies the number of results returned
	//   * 'Cursor' is returned by previous calls and specifies what page to return
	PaginationSpec *PaginationSpec `form:"PaginationSpec,omitempty" json:"PaginationSpec,omitempty"`

	// Sort The sort order of the packages
	//   * 'frequency' - The packages with the highest number of dependents
	//   * 'scorecard' - The packages with the lowest OpenSSF scorecard score
	Sort AnalyzeDependenciesParamsSort `form:"sort" json:"sort"`
}

// AnalyzeDependenciesParamsSort defines parameters for AnalyzeDependencies.
type AnalyzeDependenciesParamsSort string

// RetrieveDependenciesParams defines parameters for RetrieveDependencies.
type RetrieveDependenciesParams struct {
	// PaginationSpec The pagination configuration for the query.
	//   * 'PageSize' specifies the number of results returned
	//   * 'Cursor' is returned by previous calls and specifies what page to return
	PaginationSpec *PaginationSpec `form:"PaginationSpec,omitempty" json:"PaginationSpec,omitempty"`

	// Purl the purl of the dependent package
	Purl string `form:"purl" json:"purl"`
}

// ScoreNACDJSONRequestBody defines body for ScoreNACD for application/json ContentType.
type ScoreNACDJSONRequestBody = NACDScoreRequest
