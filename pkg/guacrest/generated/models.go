// Package generated provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen/v2 version v2.1.0 DO NOT EDIT.
package generated

import (
	"time"
)

// Defines values for AnalyzeDependenciesParamsSort.
const (
	Frequency AnalyzeDependenciesParamsSort = "frequency"
	Scorecard AnalyzeDependenciesParamsSort = "scorecard"
)

// Defines values for RetrieveDependenciesParamsLinkCondition.
const (
	Digest RetrieveDependenciesParamsLinkCondition = "digest"
	Name   RetrieveDependenciesParamsLinkCondition = "name"
)

// Error defines model for Error.
type Error struct {
	Message string `json:"Message"`
}

// HasSBOM defines model for HasSBOM.
type HasSBOM struct {
	Algorithm        string    `json:"Algorithm"`
	Collector        string    `json:"Collector"`
	Digest           string    `json:"Digest"`
	DownloadLocation string    `json:"DownloadLocation"`
	Id               string    `json:"Id"`
	KnownSince       time.Time `json:"KnownSince"`
	Origin           string    `json:"Origin"`
	URI              string    `json:"URI"`
}

// PackageName defines model for PackageName.
type PackageName struct {
	DependentCount int  `json:"DependentCount"`
	Name           Purl `json:"Name"`
}

// PaginationInfo Contains the cursor to retrieve more pages. If there are no more,  NextCursor will be nil.
type PaginationInfo struct {
	NextCursor *string `json:"NextCursor,omitempty"`
	TotalCount *int    `json:"TotalCount,omitempty"`
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
type PurlList struct {
	// PaginationInfo Contains the cursor to retrieve more pages. If there are no more,  NextCursor will be nil.
	PaginationInfo PaginationInfo `json:"PaginationInfo"`
	PurlList       []Purl         `json:"PurlList"`
}

// AnalyzeDependenciesParams defines parameters for AnalyzeDependencies.
type AnalyzeDependenciesParams struct {
	// PaginationSpec The pagination configuration for the query.
	//   * 'PageSize' specifies the number of results returned
	//   * 'Cursor' is returned by previous calls and specifies what page to return
	PaginationSpec *PaginationSpec `form:"paginationSpec,omitempty" json:"paginationSpec,omitempty"`

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
	PaginationSpec *PaginationSpec `form:"paginationSpec,omitempty" json:"paginationSpec,omitempty"`

	// LinkCondition Whether links between nouns must be made by digest or if they  can be made just by name (i.e. purl). Specify 'name' to allow using SBOMs that don't provide the digest of the subject. The default is  'digest'. To search by purl, 'name' must be specified.
	LinkCondition *RetrieveDependenciesParamsLinkCondition `form:"linkCondition,omitempty" json:"linkCondition,omitempty"`

	// Purl The purl of the dependent package.
	Purl *string `form:"purl,omitempty" json:"purl,omitempty"`

	// Digest The digest of the dependent package.
	Digest *string `form:"digest,omitempty" json:"digest,omitempty"`
}

// RetrieveDependenciesParamsLinkCondition defines parameters for RetrieveDependencies.
type RetrieveDependenciesParamsLinkCondition string

// FindLatestSBOMParams defines parameters for FindLatestSBOM.
type FindLatestSBOMParams struct {
	// PkgID The package-version level id.
	PkgID string `form:"pkgID" json:"pkgID"`
}
