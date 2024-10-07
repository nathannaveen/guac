// Package generated provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.1-0.20240823215434-d232e9efa9f5 DO NOT EDIT.
package generated

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/oapi-codegen/runtime"
	strictnethttp "github.com/oapi-codegen/runtime/strictmiddleware/nethttp"
)

// ServerInterface represents all server handlers.
type ServerInterface interface {
	// Identify the most important dependencies
	// (GET /analysis/dependencies)
	AnalyzeDependencies(w http.ResponseWriter, r *http.Request, params AnalyzeDependenciesParams)
	// Health check the server
	// (GET /healthz)
	HealthCheck(w http.ResponseWriter, r *http.Request)
	// Retrieve transitive dependencies
	// (GET /query/dependencies)
	RetrieveDependencies(w http.ResponseWriter, r *http.Request, params RetrieveDependenciesParams)
	// Get dependencies for a specific Artifact (<algorithm>:<digest>)
	// (GET /v0/artifact/{artifact}/dependencies)
	GetArtifactDependencies(w http.ResponseWriter, r *http.Request, artifact string, params GetArtifactDependenciesParams)
	// Get vulnerabilities for a specific Artifact (<algorithm>:<digest>)
	// (GET /v0/artifact/{artifact}/vulns)
	GetArtifactVulnerabilities(w http.ResponseWriter, r *http.Request, artifact string, params GetArtifactVulnerabilitiesParams)
	// Get purls related to the specific Package URL (PURL)
	// (GET /v0/package/{purl})
	GetPackagePurlsByPurl(w http.ResponseWriter, r *http.Request, purl string)
	// Get dependencies for a specific Package URL (PURL)
	// (GET /v0/package/{purl}/dependencies)
	GetPackageDependenciesByPurl(w http.ResponseWriter, r *http.Request, purl string, params GetPackageDependenciesByPurlParams)
	// Get vulnerabilities for a specific Package URL (PURL)
	// (GET /v0/package/{purl}/vulns)
	GetPackageVulnerabilitiesByPurl(w http.ResponseWriter, r *http.Request, purl string, params GetPackageVulnerabilitiesByPurlParams)
}

// Unimplemented server implementation that returns http.StatusNotImplemented for each endpoint.

type Unimplemented struct{}

// Identify the most important dependencies
// (GET /analysis/dependencies)
func (_ Unimplemented) AnalyzeDependencies(w http.ResponseWriter, r *http.Request, params AnalyzeDependenciesParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

// Health check the server
// (GET /healthz)
func (_ Unimplemented) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
}

// Retrieve transitive dependencies
// (GET /query/dependencies)
func (_ Unimplemented) RetrieveDependencies(w http.ResponseWriter, r *http.Request, params RetrieveDependenciesParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

// Get dependencies for a specific Artifact (<algorithm>:<digest>)
// (GET /v0/artifact/{artifact}/dependencies)
func (_ Unimplemented) GetArtifactDependencies(w http.ResponseWriter, r *http.Request, artifact string, params GetArtifactDependenciesParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

// Get vulnerabilities for a specific Artifact (<algorithm>:<digest>)
// (GET /v0/artifact/{artifact}/vulns)
func (_ Unimplemented) GetArtifactVulnerabilities(w http.ResponseWriter, r *http.Request, artifact string, params GetArtifactVulnerabilitiesParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

// Get purls related to the specific Package URL (PURL)
// (GET /v0/package/{purl})
func (_ Unimplemented) GetPackagePurlsByPurl(w http.ResponseWriter, r *http.Request, purl string) {
	w.WriteHeader(http.StatusNotImplemented)
}

// Get dependencies for a specific Package URL (PURL)
// (GET /v0/package/{purl}/dependencies)
func (_ Unimplemented) GetPackageDependenciesByPurl(w http.ResponseWriter, r *http.Request, purl string, params GetPackageDependenciesByPurlParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

// Get vulnerabilities for a specific Package URL (PURL)
// (GET /v0/package/{purl}/vulns)
func (_ Unimplemented) GetPackageVulnerabilitiesByPurl(w http.ResponseWriter, r *http.Request, purl string, params GetPackageVulnerabilitiesByPurlParams) {
	w.WriteHeader(http.StatusNotImplemented)
}

// ServerInterfaceWrapper converts contexts to parameters.
type ServerInterfaceWrapper struct {
	Handler            ServerInterface
	HandlerMiddlewares []MiddlewareFunc
	ErrorHandlerFunc   func(w http.ResponseWriter, r *http.Request, err error)
}

type MiddlewareFunc func(http.Handler) http.Handler

// AnalyzeDependencies operation middleware
func (siw *ServerInterfaceWrapper) AnalyzeDependencies(w http.ResponseWriter, r *http.Request) {

	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params AnalyzeDependenciesParams

	// ------------- Optional query parameter "paginationSpec" -------------

	err = runtime.BindQueryParameter("form", true, false, "paginationSpec", r.URL.Query(), &params.PaginationSpec)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "paginationSpec", Err: err})
		return
	}

	// ------------- Required query parameter "sort" -------------

	if paramValue := r.URL.Query().Get("sort"); paramValue != "" {

	} else {
		siw.ErrorHandlerFunc(w, r, &RequiredParamError{ParamName: "sort"})
		return
	}

	err = runtime.BindQueryParameter("form", true, true, "sort", r.URL.Query(), &params.Sort)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "sort", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.AnalyzeDependencies(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// HealthCheck operation middleware
func (siw *ServerInterfaceWrapper) HealthCheck(w http.ResponseWriter, r *http.Request) {

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.HealthCheck(w, r)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// RetrieveDependencies operation middleware
func (siw *ServerInterfaceWrapper) RetrieveDependencies(w http.ResponseWriter, r *http.Request) {

	var err error

	// Parameter object where we will unmarshal all parameters from the context
	var params RetrieveDependenciesParams

	// ------------- Optional query parameter "paginationSpec" -------------

	err = runtime.BindQueryParameter("form", true, false, "paginationSpec", r.URL.Query(), &params.PaginationSpec)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "paginationSpec", Err: err})
		return
	}

	// ------------- Optional query parameter "linkCondition" -------------

	err = runtime.BindQueryParameter("form", true, false, "linkCondition", r.URL.Query(), &params.LinkCondition)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "linkCondition", Err: err})
		return
	}

	// ------------- Optional query parameter "purl" -------------

	err = runtime.BindQueryParameter("form", true, false, "purl", r.URL.Query(), &params.Purl)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "purl", Err: err})
		return
	}

	// ------------- Optional query parameter "digest" -------------

	err = runtime.BindQueryParameter("form", true, false, "digest", r.URL.Query(), &params.Digest)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "digest", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.RetrieveDependencies(w, r, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// GetArtifactDependencies operation middleware
func (siw *ServerInterfaceWrapper) GetArtifactDependencies(w http.ResponseWriter, r *http.Request) {

	var err error

	// ------------- Path parameter "artifact" -------------
	var artifact string

	err = runtime.BindStyledParameterWithOptions("simple", "artifact", chi.URLParam(r, "artifact"), &artifact, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "artifact", Err: err})
		return
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params GetArtifactDependenciesParams

	// ------------- Optional query parameter "latestSBOM" -------------

	err = runtime.BindQueryParameter("form", true, false, "latestSBOM", r.URL.Query(), &params.LatestSBOM)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "latestSBOM", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetArtifactDependencies(w, r, artifact, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// GetArtifactVulnerabilities operation middleware
func (siw *ServerInterfaceWrapper) GetArtifactVulnerabilities(w http.ResponseWriter, r *http.Request) {

	var err error

	// ------------- Path parameter "artifact" -------------
	var artifact string

	err = runtime.BindStyledParameterWithOptions("simple", "artifact", chi.URLParam(r, "artifact"), &artifact, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "artifact", Err: err})
		return
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params GetArtifactVulnerabilitiesParams

	// ------------- Optional query parameter "latestSBOM" -------------

	err = runtime.BindQueryParameter("form", true, false, "latestSBOM", r.URL.Query(), &params.LatestSBOM)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "latestSBOM", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetArtifactVulnerabilities(w, r, artifact, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// GetPackagePurlsByPurl operation middleware
func (siw *ServerInterfaceWrapper) GetPackagePurlsByPurl(w http.ResponseWriter, r *http.Request) {

	var err error

	// ------------- Path parameter "purl" -------------
	var purl string

	err = runtime.BindStyledParameterWithOptions("simple", "purl", chi.URLParam(r, "purl"), &purl, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "purl", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetPackagePurlsByPurl(w, r, purl)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// GetPackageDependenciesByPurl operation middleware
func (siw *ServerInterfaceWrapper) GetPackageDependenciesByPurl(w http.ResponseWriter, r *http.Request) {

	var err error

	// ------------- Path parameter "purl" -------------
	var purl string

	err = runtime.BindStyledParameterWithOptions("simple", "purl", chi.URLParam(r, "purl"), &purl, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "purl", Err: err})
		return
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params GetPackageDependenciesByPurlParams

	// ------------- Optional query parameter "latestSBOM" -------------

	err = runtime.BindQueryParameter("form", true, false, "latestSBOM", r.URL.Query(), &params.LatestSBOM)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "latestSBOM", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetPackageDependenciesByPurl(w, r, purl, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

// GetPackageVulnerabilitiesByPurl operation middleware
func (siw *ServerInterfaceWrapper) GetPackageVulnerabilitiesByPurl(w http.ResponseWriter, r *http.Request) {

	var err error

	// ------------- Path parameter "purl" -------------
	var purl string

	err = runtime.BindStyledParameterWithOptions("simple", "purl", chi.URLParam(r, "purl"), &purl, runtime.BindStyledParameterOptions{ParamLocation: runtime.ParamLocationPath, Explode: false, Required: true})
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "purl", Err: err})
		return
	}

	// Parameter object where we will unmarshal all parameters from the context
	var params GetPackageVulnerabilitiesByPurlParams

	// ------------- Optional query parameter "latestSBOM" -------------

	err = runtime.BindQueryParameter("form", true, false, "latestSBOM", r.URL.Query(), &params.LatestSBOM)
	if err != nil {
		siw.ErrorHandlerFunc(w, r, &InvalidParamFormatError{ParamName: "latestSBOM", Err: err})
		return
	}

	handler := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		siw.Handler.GetPackageVulnerabilitiesByPurl(w, r, purl, params)
	}))

	for _, middleware := range siw.HandlerMiddlewares {
		handler = middleware(handler)
	}

	handler.ServeHTTP(w, r)
}

type UnescapedCookieParamError struct {
	ParamName string
	Err       error
}

func (e *UnescapedCookieParamError) Error() string {
	return fmt.Sprintf("error unescaping cookie parameter '%s'", e.ParamName)
}

func (e *UnescapedCookieParamError) Unwrap() error {
	return e.Err
}

type UnmarshalingParamError struct {
	ParamName string
	Err       error
}

func (e *UnmarshalingParamError) Error() string {
	return fmt.Sprintf("Error unmarshaling parameter %s as JSON: %s", e.ParamName, e.Err.Error())
}

func (e *UnmarshalingParamError) Unwrap() error {
	return e.Err
}

type RequiredParamError struct {
	ParamName string
}

func (e *RequiredParamError) Error() string {
	return fmt.Sprintf("Query argument %s is required, but not found", e.ParamName)
}

type RequiredHeaderError struct {
	ParamName string
	Err       error
}

func (e *RequiredHeaderError) Error() string {
	return fmt.Sprintf("Header parameter %s is required, but not found", e.ParamName)
}

func (e *RequiredHeaderError) Unwrap() error {
	return e.Err
}

type InvalidParamFormatError struct {
	ParamName string
	Err       error
}

func (e *InvalidParamFormatError) Error() string {
	return fmt.Sprintf("Invalid format for parameter %s: %s", e.ParamName, e.Err.Error())
}

func (e *InvalidParamFormatError) Unwrap() error {
	return e.Err
}

type TooManyValuesForParamError struct {
	ParamName string
	Count     int
}

func (e *TooManyValuesForParamError) Error() string {
	return fmt.Sprintf("Expected one value for %s, got %d", e.ParamName, e.Count)
}

// Handler creates http.Handler with routing matching OpenAPI spec.
func Handler(si ServerInterface) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{})
}

type ChiServerOptions struct {
	BaseURL          string
	BaseRouter       chi.Router
	Middlewares      []MiddlewareFunc
	ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

// HandlerFromMux creates http.Handler with routing matching OpenAPI spec based on the provided mux.
func HandlerFromMux(si ServerInterface, r chi.Router) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseRouter: r,
	})
}

func HandlerFromMuxWithBaseURL(si ServerInterface, r chi.Router, baseURL string) http.Handler {
	return HandlerWithOptions(si, ChiServerOptions{
		BaseURL:    baseURL,
		BaseRouter: r,
	})
}

// HandlerWithOptions creates http.Handler with additional options
func HandlerWithOptions(si ServerInterface, options ChiServerOptions) http.Handler {
	r := options.BaseRouter

	if r == nil {
		r = chi.NewRouter()
	}
	if options.ErrorHandlerFunc == nil {
		options.ErrorHandlerFunc = func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
	wrapper := ServerInterfaceWrapper{
		Handler:            si,
		HandlerMiddlewares: options.Middlewares,
		ErrorHandlerFunc:   options.ErrorHandlerFunc,
	}

	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/analysis/dependencies", wrapper.AnalyzeDependencies)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/healthz", wrapper.HealthCheck)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/query/dependencies", wrapper.RetrieveDependencies)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/v0/artifact/{artifact}/dependencies", wrapper.GetArtifactDependencies)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/v0/artifact/{artifact}/vulns", wrapper.GetArtifactVulnerabilities)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/v0/package/{purl}", wrapper.GetPackagePurlsByPurl)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/v0/package/{purl}/dependencies", wrapper.GetPackageDependenciesByPurl)
	})
	r.Group(func(r chi.Router) {
		r.Get(options.BaseURL+"/v0/package/{purl}/vulns", wrapper.GetPackageVulnerabilitiesByPurl)
	})

	return r
}

type BadGatewayJSONResponse Error

type BadRequestJSONResponse Error

type InternalServerErrorJSONResponse Error

type PackageNameListJSONResponse []PackageName

type PurlListJSONResponse struct {
	// PaginationInfo Contains the cursor to retrieve more pages. If there are no more,  NextCursor will be nil.
	PaginationInfo PaginationInfo `json:"PaginationInfo"`
	PurlList       []Purl         `json:"PurlList"`
}

type VulnerabilityListJSONResponse []Vulnerability

type AnalyzeDependenciesRequestObject struct {
	Params AnalyzeDependenciesParams
}

type AnalyzeDependenciesResponseObject interface {
	VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error
}

type AnalyzeDependencies200JSONResponse struct{ PackageNameListJSONResponse }

func (response AnalyzeDependencies200JSONResponse) VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type AnalyzeDependencies400JSONResponse struct{ BadRequestJSONResponse }

func (response AnalyzeDependencies400JSONResponse) VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type AnalyzeDependencies500JSONResponse struct {
	InternalServerErrorJSONResponse
}

func (response AnalyzeDependencies500JSONResponse) VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type AnalyzeDependencies502JSONResponse struct{ BadGatewayJSONResponse }

func (response AnalyzeDependencies502JSONResponse) VisitAnalyzeDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(502)

	return json.NewEncoder(w).Encode(response)
}

type HealthCheckRequestObject struct {
}

type HealthCheckResponseObject interface {
	VisitHealthCheckResponse(w http.ResponseWriter) error
}

type HealthCheck200JSONResponse string

func (response HealthCheck200JSONResponse) VisitHealthCheckResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type RetrieveDependenciesRequestObject struct {
	Params RetrieveDependenciesParams
}

type RetrieveDependenciesResponseObject interface {
	VisitRetrieveDependenciesResponse(w http.ResponseWriter) error
}

type RetrieveDependencies200JSONResponse struct{ PurlListJSONResponse }

func (response RetrieveDependencies200JSONResponse) VisitRetrieveDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type RetrieveDependencies400JSONResponse struct{ BadRequestJSONResponse }

func (response RetrieveDependencies400JSONResponse) VisitRetrieveDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type RetrieveDependencies500JSONResponse struct {
	InternalServerErrorJSONResponse
}

func (response RetrieveDependencies500JSONResponse) VisitRetrieveDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type RetrieveDependencies502JSONResponse struct{ BadGatewayJSONResponse }

func (response RetrieveDependencies502JSONResponse) VisitRetrieveDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(502)

	return json.NewEncoder(w).Encode(response)
}

type GetArtifactDependenciesRequestObject struct {
	Artifact string `json:"artifact"`
	Params   GetArtifactDependenciesParams
}

type GetArtifactDependenciesResponseObject interface {
	VisitGetArtifactDependenciesResponse(w http.ResponseWriter) error
}

type GetArtifactDependencies200JSONResponse struct{ PurlListJSONResponse }

func (response GetArtifactDependencies200JSONResponse) VisitGetArtifactDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetArtifactDependencies400JSONResponse struct{ BadRequestJSONResponse }

func (response GetArtifactDependencies400JSONResponse) VisitGetArtifactDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type GetArtifactDependencies500JSONResponse struct {
	InternalServerErrorJSONResponse
}

func (response GetArtifactDependencies500JSONResponse) VisitGetArtifactDependenciesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type GetArtifactVulnerabilitiesRequestObject struct {
	Artifact string `json:"artifact"`
	Params   GetArtifactVulnerabilitiesParams
}

type GetArtifactVulnerabilitiesResponseObject interface {
	VisitGetArtifactVulnerabilitiesResponse(w http.ResponseWriter) error
}

type GetArtifactVulnerabilities200JSONResponse struct{ VulnerabilityListJSONResponse }

func (response GetArtifactVulnerabilities200JSONResponse) VisitGetArtifactVulnerabilitiesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetArtifactVulnerabilities400JSONResponse struct{ BadRequestJSONResponse }

func (response GetArtifactVulnerabilities400JSONResponse) VisitGetArtifactVulnerabilitiesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type GetArtifactVulnerabilities500JSONResponse struct {
	InternalServerErrorJSONResponse
}

func (response GetArtifactVulnerabilities500JSONResponse) VisitGetArtifactVulnerabilitiesResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type GetPackagePurlsByPurlRequestObject struct {
	Purl string `json:"purl"`
}

type GetPackagePurlsByPurlResponseObject interface {
	VisitGetPackagePurlsByPurlResponse(w http.ResponseWriter) error
}

type GetPackagePurlsByPurl200JSONResponse []string

func (response GetPackagePurlsByPurl200JSONResponse) VisitGetPackagePurlsByPurlResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetPackagePurlsByPurl400JSONResponse struct{ BadRequestJSONResponse }

func (response GetPackagePurlsByPurl400JSONResponse) VisitGetPackagePurlsByPurlResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type GetPackagePurlsByPurl500JSONResponse struct {
	InternalServerErrorJSONResponse
}

func (response GetPackagePurlsByPurl500JSONResponse) VisitGetPackagePurlsByPurlResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type GetPackageDependenciesByPurlRequestObject struct {
	Purl   string `json:"purl"`
	Params GetPackageDependenciesByPurlParams
}

type GetPackageDependenciesByPurlResponseObject interface {
	VisitGetPackageDependenciesByPurlResponse(w http.ResponseWriter) error
}

type GetPackageDependenciesByPurl200JSONResponse struct{ PurlListJSONResponse }

func (response GetPackageDependenciesByPurl200JSONResponse) VisitGetPackageDependenciesByPurlResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetPackageDependenciesByPurl400JSONResponse struct{ BadRequestJSONResponse }

func (response GetPackageDependenciesByPurl400JSONResponse) VisitGetPackageDependenciesByPurlResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type GetPackageDependenciesByPurl500JSONResponse struct {
	InternalServerErrorJSONResponse
}

func (response GetPackageDependenciesByPurl500JSONResponse) VisitGetPackageDependenciesByPurlResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

type GetPackageVulnerabilitiesByPurlRequestObject struct {
	Purl   string `json:"purl"`
	Params GetPackageVulnerabilitiesByPurlParams
}

type GetPackageVulnerabilitiesByPurlResponseObject interface {
	VisitGetPackageVulnerabilitiesByPurlResponse(w http.ResponseWriter) error
}

type GetPackageVulnerabilitiesByPurl200JSONResponse struct{ VulnerabilityListJSONResponse }

func (response GetPackageVulnerabilitiesByPurl200JSONResponse) VisitGetPackageVulnerabilitiesByPurlResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)

	return json.NewEncoder(w).Encode(response)
}

type GetPackageVulnerabilitiesByPurl400JSONResponse struct{ BadRequestJSONResponse }

func (response GetPackageVulnerabilitiesByPurl400JSONResponse) VisitGetPackageVulnerabilitiesByPurlResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(400)

	return json.NewEncoder(w).Encode(response)
}

type GetPackageVulnerabilitiesByPurl500JSONResponse struct {
	InternalServerErrorJSONResponse
}

func (response GetPackageVulnerabilitiesByPurl500JSONResponse) VisitGetPackageVulnerabilitiesByPurlResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)

	return json.NewEncoder(w).Encode(response)
}

// StrictServerInterface represents all server handlers.
type StrictServerInterface interface {
	// Identify the most important dependencies
	// (GET /analysis/dependencies)
	AnalyzeDependencies(ctx context.Context, request AnalyzeDependenciesRequestObject) (AnalyzeDependenciesResponseObject, error)
	// Health check the server
	// (GET /healthz)
	HealthCheck(ctx context.Context, request HealthCheckRequestObject) (HealthCheckResponseObject, error)
	// Retrieve transitive dependencies
	// (GET /query/dependencies)
	RetrieveDependencies(ctx context.Context, request RetrieveDependenciesRequestObject) (RetrieveDependenciesResponseObject, error)
	// Get dependencies for a specific Artifact (<algorithm>:<digest>)
	// (GET /v0/artifact/{artifact}/dependencies)
	GetArtifactDependencies(ctx context.Context, request GetArtifactDependenciesRequestObject) (GetArtifactDependenciesResponseObject, error)
	// Get vulnerabilities for a specific Artifact (<algorithm>:<digest>)
	// (GET /v0/artifact/{artifact}/vulns)
	GetArtifactVulnerabilities(ctx context.Context, request GetArtifactVulnerabilitiesRequestObject) (GetArtifactVulnerabilitiesResponseObject, error)
	// Get purls related to the specific Package URL (PURL)
	// (GET /v0/package/{purl})
	GetPackagePurlsByPurl(ctx context.Context, request GetPackagePurlsByPurlRequestObject) (GetPackagePurlsByPurlResponseObject, error)
	// Get dependencies for a specific Package URL (PURL)
	// (GET /v0/package/{purl}/dependencies)
	GetPackageDependenciesByPurl(ctx context.Context, request GetPackageDependenciesByPurlRequestObject) (GetPackageDependenciesByPurlResponseObject, error)
	// Get vulnerabilities for a specific Package URL (PURL)
	// (GET /v0/package/{purl}/vulns)
	GetPackageVulnerabilitiesByPurl(ctx context.Context, request GetPackageVulnerabilitiesByPurlRequestObject) (GetPackageVulnerabilitiesByPurlResponseObject, error)
}

type StrictHandlerFunc = strictnethttp.StrictHTTPHandlerFunc
type StrictMiddlewareFunc = strictnethttp.StrictHTTPMiddlewareFunc

type StrictHTTPServerOptions struct {
	RequestErrorHandlerFunc  func(w http.ResponseWriter, r *http.Request, err error)
	ResponseErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, err error)
}

func NewStrictHandler(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc) ServerInterface {
	return &strictHandler{ssi: ssi, middlewares: middlewares, options: StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		},
	}}
}

func NewStrictHandlerWithOptions(ssi StrictServerInterface, middlewares []StrictMiddlewareFunc, options StrictHTTPServerOptions) ServerInterface {
	return &strictHandler{ssi: ssi, middlewares: middlewares, options: options}
}

type strictHandler struct {
	ssi         StrictServerInterface
	middlewares []StrictMiddlewareFunc
	options     StrictHTTPServerOptions
}

// AnalyzeDependencies operation middleware
func (sh *strictHandler) AnalyzeDependencies(w http.ResponseWriter, r *http.Request, params AnalyzeDependenciesParams) {
	var request AnalyzeDependenciesRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.AnalyzeDependencies(ctx, request.(AnalyzeDependenciesRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "AnalyzeDependencies")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(AnalyzeDependenciesResponseObject); ok {
		if err := validResponse.VisitAnalyzeDependenciesResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// HealthCheck operation middleware
func (sh *strictHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	var request HealthCheckRequestObject

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.HealthCheck(ctx, request.(HealthCheckRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "HealthCheck")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(HealthCheckResponseObject); ok {
		if err := validResponse.VisitHealthCheckResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// RetrieveDependencies operation middleware
func (sh *strictHandler) RetrieveDependencies(w http.ResponseWriter, r *http.Request, params RetrieveDependenciesParams) {
	var request RetrieveDependenciesRequestObject

	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.RetrieveDependencies(ctx, request.(RetrieveDependenciesRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "RetrieveDependencies")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(RetrieveDependenciesResponseObject); ok {
		if err := validResponse.VisitRetrieveDependenciesResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// GetArtifactDependencies operation middleware
func (sh *strictHandler) GetArtifactDependencies(w http.ResponseWriter, r *http.Request, artifact string, params GetArtifactDependenciesParams) {
	var request GetArtifactDependenciesRequestObject

	request.Artifact = artifact
	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.GetArtifactDependencies(ctx, request.(GetArtifactDependenciesRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetArtifactDependencies")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(GetArtifactDependenciesResponseObject); ok {
		if err := validResponse.VisitGetArtifactDependenciesResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// GetArtifactVulnerabilities operation middleware
func (sh *strictHandler) GetArtifactVulnerabilities(w http.ResponseWriter, r *http.Request, artifact string, params GetArtifactVulnerabilitiesParams) {
	var request GetArtifactVulnerabilitiesRequestObject

	request.Artifact = artifact
	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.GetArtifactVulnerabilities(ctx, request.(GetArtifactVulnerabilitiesRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetArtifactVulnerabilities")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(GetArtifactVulnerabilitiesResponseObject); ok {
		if err := validResponse.VisitGetArtifactVulnerabilitiesResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// GetPackagePurlsByPurl operation middleware
func (sh *strictHandler) GetPackagePurlsByPurl(w http.ResponseWriter, r *http.Request, purl string) {
	var request GetPackagePurlsByPurlRequestObject

	request.Purl = purl

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.GetPackagePurlsByPurl(ctx, request.(GetPackagePurlsByPurlRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetPackagePurlsByPurl")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(GetPackagePurlsByPurlResponseObject); ok {
		if err := validResponse.VisitGetPackagePurlsByPurlResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// GetPackageDependenciesByPurl operation middleware
func (sh *strictHandler) GetPackageDependenciesByPurl(w http.ResponseWriter, r *http.Request, purl string, params GetPackageDependenciesByPurlParams) {
	var request GetPackageDependenciesByPurlRequestObject

	request.Purl = purl
	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.GetPackageDependenciesByPurl(ctx, request.(GetPackageDependenciesByPurlRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetPackageDependenciesByPurl")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(GetPackageDependenciesByPurlResponseObject); ok {
		if err := validResponse.VisitGetPackageDependenciesByPurlResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}

// GetPackageVulnerabilitiesByPurl operation middleware
func (sh *strictHandler) GetPackageVulnerabilitiesByPurl(w http.ResponseWriter, r *http.Request, purl string, params GetPackageVulnerabilitiesByPurlParams) {
	var request GetPackageVulnerabilitiesByPurlRequestObject

	request.Purl = purl
	request.Params = params

	handler := func(ctx context.Context, w http.ResponseWriter, r *http.Request, request interface{}) (interface{}, error) {
		return sh.ssi.GetPackageVulnerabilitiesByPurl(ctx, request.(GetPackageVulnerabilitiesByPurlRequestObject))
	}
	for _, middleware := range sh.middlewares {
		handler = middleware(handler, "GetPackageVulnerabilitiesByPurl")
	}

	response, err := handler(r.Context(), w, r, request)

	if err != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, err)
	} else if validResponse, ok := response.(GetPackageVulnerabilitiesByPurlResponseObject); ok {
		if err := validResponse.VisitGetPackageVulnerabilitiesByPurlResponse(w); err != nil {
			sh.options.ResponseErrorHandlerFunc(w, r, err)
		}
	} else if response != nil {
		sh.options.ResponseErrorHandlerFunc(w, r, fmt.Errorf("unexpected response type: %T", response))
	}
}
