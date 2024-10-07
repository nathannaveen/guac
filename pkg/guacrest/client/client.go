// Package client provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.1-0.20240823215434-d232e9efa9f5 DO NOT EDIT.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/oapi-codegen/runtime"
)

// RequestEditorFn  is the function signature for the RequestEditor callback function
type RequestEditorFn func(ctx context.Context, req *http.Request) error

// Doer performs HTTP requests.
//
// The standard http.Client implements this interface.
type HttpRequestDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client which conforms to the OpenAPI3 specification for this service.
type Client struct {
	// The endpoint of the server conforming to this interface, with scheme,
	// https://api.deepmap.com for example. This can contain a path relative
	// to the server, such as https://api.deepmap.com/dev-test, and all the
	// paths in the swagger spec will be appended to the server.
	Server string

	// Doer for performing requests, typically a *http.Client with any
	// customized settings, such as certificate chains.
	Client HttpRequestDoer

	// A list of callbacks for modifying requests which are generated before sending over
	// the network.
	RequestEditors []RequestEditorFn
}

// ClientOption allows setting custom parameters during construction
type ClientOption func(*Client) error

// Creates a new Client, with reasonable defaults
func NewClient(server string, opts ...ClientOption) (*Client, error) {
	// create a client with sane default values
	client := Client{
		Server: server,
	}
	// mutate client and add all optional params
	for _, o := range opts {
		if err := o(&client); err != nil {
			return nil, err
		}
	}
	// ensure the server URL always has a trailing slash
	if !strings.HasSuffix(client.Server, "/") {
		client.Server += "/"
	}
	// create httpClient, if not already present
	if client.Client == nil {
		client.Client = &http.Client{}
	}
	return &client, nil
}

// WithHTTPClient allows overriding the default Doer, which is
// automatically created using http.Client. This is useful for tests.
func WithHTTPClient(doer HttpRequestDoer) ClientOption {
	return func(c *Client) error {
		c.Client = doer
		return nil
	}
}

// WithRequestEditorFn allows setting up a callback function, which will be
// called right before sending the request. This can be used to mutate the request.
func WithRequestEditorFn(fn RequestEditorFn) ClientOption {
	return func(c *Client) error {
		c.RequestEditors = append(c.RequestEditors, fn)
		return nil
	}
}

// The interface specification for the client above.
type ClientInterface interface {
	// AnalyzeDependencies request
	AnalyzeDependencies(ctx context.Context, params *AnalyzeDependenciesParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// HealthCheck request
	HealthCheck(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error)

	// RetrieveDependencies request
	RetrieveDependencies(ctx context.Context, params *RetrieveDependenciesParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetArtifactDependencies request
	GetArtifactDependencies(ctx context.Context, artifact string, params *GetArtifactDependenciesParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetArtifactVulnerabilities request
	GetArtifactVulnerabilities(ctx context.Context, artifact string, params *GetArtifactVulnerabilitiesParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetPackagePurlsByPurl request
	GetPackagePurlsByPurl(ctx context.Context, purl string, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetPackageDependenciesByPurl request
	GetPackageDependenciesByPurl(ctx context.Context, purl string, params *GetPackageDependenciesByPurlParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// GetPackageVulnerabilitiesByPurl request
	GetPackageVulnerabilitiesByPurl(ctx context.Context, purl string, params *GetPackageVulnerabilitiesByPurlParams, reqEditors ...RequestEditorFn) (*http.Response, error)
}

func (c *Client) AnalyzeDependencies(ctx context.Context, params *AnalyzeDependenciesParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewAnalyzeDependenciesRequest(c.Server, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) HealthCheck(ctx context.Context, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewHealthCheckRequest(c.Server)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) RetrieveDependencies(ctx context.Context, params *RetrieveDependenciesParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewRetrieveDependenciesRequest(c.Server, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetArtifactDependencies(ctx context.Context, artifact string, params *GetArtifactDependenciesParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetArtifactDependenciesRequest(c.Server, artifact, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetArtifactVulnerabilities(ctx context.Context, artifact string, params *GetArtifactVulnerabilitiesParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetArtifactVulnerabilitiesRequest(c.Server, artifact, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetPackagePurlsByPurl(ctx context.Context, purl string, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetPackagePurlsByPurlRequest(c.Server, purl)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetPackageDependenciesByPurl(ctx context.Context, purl string, params *GetPackageDependenciesByPurlParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetPackageDependenciesByPurlRequest(c.Server, purl, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) GetPackageVulnerabilitiesByPurl(ctx context.Context, purl string, params *GetPackageVulnerabilitiesByPurlParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewGetPackageVulnerabilitiesByPurlRequest(c.Server, purl, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

// NewAnalyzeDependenciesRequest generates requests for AnalyzeDependencies
func NewAnalyzeDependenciesRequest(server string, params *AnalyzeDependenciesParams) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/analysis/dependencies")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if params.PaginationSpec != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "paginationSpec", runtime.ParamLocationQuery, *params.PaginationSpec); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "sort", runtime.ParamLocationQuery, params.Sort); err != nil {
			return nil, err
		} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
			return nil, err
		} else {
			for k, v := range parsed {
				for _, v2 := range v {
					queryValues.Add(k, v2)
				}
			}
		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewHealthCheckRequest generates requests for HealthCheck
func NewHealthCheckRequest(server string) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/healthz")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewRetrieveDependenciesRequest generates requests for RetrieveDependencies
func NewRetrieveDependenciesRequest(server string, params *RetrieveDependenciesParams) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/query/dependencies")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if params.PaginationSpec != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "paginationSpec", runtime.ParamLocationQuery, *params.PaginationSpec); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		if params.LinkCondition != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "linkCondition", runtime.ParamLocationQuery, *params.LinkCondition); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		if params.Purl != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "purl", runtime.ParamLocationQuery, *params.Purl); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		if params.Digest != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "digest", runtime.ParamLocationQuery, *params.Digest); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetArtifactDependenciesRequest generates requests for GetArtifactDependencies
func NewGetArtifactDependenciesRequest(server string, artifact string, params *GetArtifactDependenciesParams) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "artifact", runtime.ParamLocationPath, artifact)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v0/artifact/%s/dependencies", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if params.LatestSBOM != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "latestSBOM", runtime.ParamLocationQuery, *params.LatestSBOM); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetArtifactVulnerabilitiesRequest generates requests for GetArtifactVulnerabilities
func NewGetArtifactVulnerabilitiesRequest(server string, artifact string, params *GetArtifactVulnerabilitiesParams) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "artifact", runtime.ParamLocationPath, artifact)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v0/artifact/%s/vulns", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if params.LatestSBOM != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "latestSBOM", runtime.ParamLocationQuery, *params.LatestSBOM); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetPackagePurlsByPurlRequest generates requests for GetPackagePurlsByPurl
func NewGetPackagePurlsByPurlRequest(server string, purl string) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "purl", runtime.ParamLocationPath, purl)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v0/package/%s", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetPackageDependenciesByPurlRequest generates requests for GetPackageDependenciesByPurl
func NewGetPackageDependenciesByPurlRequest(server string, purl string, params *GetPackageDependenciesByPurlParams) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "purl", runtime.ParamLocationPath, purl)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v0/package/%s/dependencies", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if params.LatestSBOM != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "latestSBOM", runtime.ParamLocationQuery, *params.LatestSBOM); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

// NewGetPackageVulnerabilitiesByPurlRequest generates requests for GetPackageVulnerabilitiesByPurl
func NewGetPackageVulnerabilitiesByPurlRequest(server string, purl string, params *GetPackageVulnerabilitiesByPurlParams) (*http.Request, error) {
	var err error

	var pathParam0 string

	pathParam0, err = runtime.StyleParamWithLocation("simple", false, "purl", runtime.ParamLocationPath, purl)
	if err != nil {
		return nil, err
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/v0/package/%s/vulns", pathParam0)
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if params.LatestSBOM != nil {

			if queryFrag, err := runtime.StyleParamWithLocation("form", true, "latestSBOM", runtime.ParamLocationQuery, *params.LatestSBOM); err != nil {
				return nil, err
			} else if parsed, err := url.ParseQuery(queryFrag); err != nil {
				return nil, err
			} else {
				for k, v := range parsed {
					for _, v2 := range v {
						queryValues.Add(k, v2)
					}
				}
			}

		}

		queryURL.RawQuery = queryValues.Encode()
	}

	req, err := http.NewRequest("GET", queryURL.String(), nil)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (c *Client) applyEditors(ctx context.Context, req *http.Request, additionalEditors []RequestEditorFn) error {
	for _, r := range c.RequestEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	for _, r := range additionalEditors {
		if err := r(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

// ClientWithResponses builds on ClientInterface to offer response payloads
type ClientWithResponses struct {
	ClientInterface
}

// NewClientWithResponses creates a new ClientWithResponses, which wraps
// Client with return type handling
func NewClientWithResponses(server string, opts ...ClientOption) (*ClientWithResponses, error) {
	client, err := NewClient(server, opts...)
	if err != nil {
		return nil, err
	}
	return &ClientWithResponses{client}, nil
}

// WithBaseURL overrides the baseURL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) error {
		newBaseURL, err := url.Parse(baseURL)
		if err != nil {
			return err
		}
		c.Server = newBaseURL.String()
		return nil
	}
}

// ClientWithResponsesInterface is the interface specification for the client with responses above.
type ClientWithResponsesInterface interface {
	// AnalyzeDependenciesWithResponse request
	AnalyzeDependenciesWithResponse(ctx context.Context, params *AnalyzeDependenciesParams, reqEditors ...RequestEditorFn) (*AnalyzeDependenciesResponse, error)

	// HealthCheckWithResponse request
	HealthCheckWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*HealthCheckResponse, error)

	// RetrieveDependenciesWithResponse request
	RetrieveDependenciesWithResponse(ctx context.Context, params *RetrieveDependenciesParams, reqEditors ...RequestEditorFn) (*RetrieveDependenciesResponse, error)

	// GetArtifactDependenciesWithResponse request
	GetArtifactDependenciesWithResponse(ctx context.Context, artifact string, params *GetArtifactDependenciesParams, reqEditors ...RequestEditorFn) (*GetArtifactDependenciesResponse, error)

	// GetArtifactVulnerabilitiesWithResponse request
	GetArtifactVulnerabilitiesWithResponse(ctx context.Context, artifact string, params *GetArtifactVulnerabilitiesParams, reqEditors ...RequestEditorFn) (*GetArtifactVulnerabilitiesResponse, error)

	// GetPackagePurlsByPurlWithResponse request
	GetPackagePurlsByPurlWithResponse(ctx context.Context, purl string, reqEditors ...RequestEditorFn) (*GetPackagePurlsByPurlResponse, error)

	// GetPackageDependenciesByPurlWithResponse request
	GetPackageDependenciesByPurlWithResponse(ctx context.Context, purl string, params *GetPackageDependenciesByPurlParams, reqEditors ...RequestEditorFn) (*GetPackageDependenciesByPurlResponse, error)

	// GetPackageVulnerabilitiesByPurlWithResponse request
	GetPackageVulnerabilitiesByPurlWithResponse(ctx context.Context, purl string, params *GetPackageVulnerabilitiesByPurlParams, reqEditors ...RequestEditorFn) (*GetPackageVulnerabilitiesByPurlResponse, error)
}

type AnalyzeDependenciesResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *PackageNameList
	JSON400      *BadRequest
	JSON500      *InternalServerError
	JSON502      *BadGateway
}

// Status returns HTTPResponse.Status
func (r AnalyzeDependenciesResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r AnalyzeDependenciesResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type HealthCheckResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *string
}

// Status returns HTTPResponse.Status
func (r HealthCheckResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r HealthCheckResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type RetrieveDependenciesResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *PurlList
	JSON400      *BadRequest
	JSON500      *InternalServerError
	JSON502      *BadGateway
}

// Status returns HTTPResponse.Status
func (r RetrieveDependenciesResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r RetrieveDependenciesResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetArtifactDependenciesResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *PurlList
	JSON400      *BadRequest
	JSON500      *InternalServerError
}

// Status returns HTTPResponse.Status
func (r GetArtifactDependenciesResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetArtifactDependenciesResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetArtifactVulnerabilitiesResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *VulnerabilityList
	JSON400      *BadRequest
	JSON500      *InternalServerError
}

// Status returns HTTPResponse.Status
func (r GetArtifactVulnerabilitiesResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetArtifactVulnerabilitiesResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetPackagePurlsByPurlResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *[]string
	JSON400      *BadRequest
	JSON500      *InternalServerError
}

// Status returns HTTPResponse.Status
func (r GetPackagePurlsByPurlResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetPackagePurlsByPurlResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetPackageDependenciesByPurlResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *PurlList
	JSON400      *BadRequest
	JSON500      *InternalServerError
}

// Status returns HTTPResponse.Status
func (r GetPackageDependenciesByPurlResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetPackageDependenciesByPurlResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type GetPackageVulnerabilitiesByPurlResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *VulnerabilityList
	JSON400      *BadRequest
	JSON500      *InternalServerError
}

// Status returns HTTPResponse.Status
func (r GetPackageVulnerabilitiesByPurlResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r GetPackageVulnerabilitiesByPurlResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

// AnalyzeDependenciesWithResponse request returning *AnalyzeDependenciesResponse
func (c *ClientWithResponses) AnalyzeDependenciesWithResponse(ctx context.Context, params *AnalyzeDependenciesParams, reqEditors ...RequestEditorFn) (*AnalyzeDependenciesResponse, error) {
	rsp, err := c.AnalyzeDependencies(ctx, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseAnalyzeDependenciesResponse(rsp)
}

// HealthCheckWithResponse request returning *HealthCheckResponse
func (c *ClientWithResponses) HealthCheckWithResponse(ctx context.Context, reqEditors ...RequestEditorFn) (*HealthCheckResponse, error) {
	rsp, err := c.HealthCheck(ctx, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseHealthCheckResponse(rsp)
}

// RetrieveDependenciesWithResponse request returning *RetrieveDependenciesResponse
func (c *ClientWithResponses) RetrieveDependenciesWithResponse(ctx context.Context, params *RetrieveDependenciesParams, reqEditors ...RequestEditorFn) (*RetrieveDependenciesResponse, error) {
	rsp, err := c.RetrieveDependencies(ctx, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseRetrieveDependenciesResponse(rsp)
}

// GetArtifactDependenciesWithResponse request returning *GetArtifactDependenciesResponse
func (c *ClientWithResponses) GetArtifactDependenciesWithResponse(ctx context.Context, artifact string, params *GetArtifactDependenciesParams, reqEditors ...RequestEditorFn) (*GetArtifactDependenciesResponse, error) {
	rsp, err := c.GetArtifactDependencies(ctx, artifact, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetArtifactDependenciesResponse(rsp)
}

// GetArtifactVulnerabilitiesWithResponse request returning *GetArtifactVulnerabilitiesResponse
func (c *ClientWithResponses) GetArtifactVulnerabilitiesWithResponse(ctx context.Context, artifact string, params *GetArtifactVulnerabilitiesParams, reqEditors ...RequestEditorFn) (*GetArtifactVulnerabilitiesResponse, error) {
	rsp, err := c.GetArtifactVulnerabilities(ctx, artifact, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetArtifactVulnerabilitiesResponse(rsp)
}

// GetPackagePurlsByPurlWithResponse request returning *GetPackagePurlsByPurlResponse
func (c *ClientWithResponses) GetPackagePurlsByPurlWithResponse(ctx context.Context, purl string, reqEditors ...RequestEditorFn) (*GetPackagePurlsByPurlResponse, error) {
	rsp, err := c.GetPackagePurlsByPurl(ctx, purl, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetPackagePurlsByPurlResponse(rsp)
}

// GetPackageDependenciesByPurlWithResponse request returning *GetPackageDependenciesByPurlResponse
func (c *ClientWithResponses) GetPackageDependenciesByPurlWithResponse(ctx context.Context, purl string, params *GetPackageDependenciesByPurlParams, reqEditors ...RequestEditorFn) (*GetPackageDependenciesByPurlResponse, error) {
	rsp, err := c.GetPackageDependenciesByPurl(ctx, purl, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetPackageDependenciesByPurlResponse(rsp)
}

// GetPackageVulnerabilitiesByPurlWithResponse request returning *GetPackageVulnerabilitiesByPurlResponse
func (c *ClientWithResponses) GetPackageVulnerabilitiesByPurlWithResponse(ctx context.Context, purl string, params *GetPackageVulnerabilitiesByPurlParams, reqEditors ...RequestEditorFn) (*GetPackageVulnerabilitiesByPurlResponse, error) {
	rsp, err := c.GetPackageVulnerabilitiesByPurl(ctx, purl, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseGetPackageVulnerabilitiesByPurlResponse(rsp)
}

// ParseAnalyzeDependenciesResponse parses an HTTP response from a AnalyzeDependenciesWithResponse call
func ParseAnalyzeDependenciesResponse(rsp *http.Response) (*AnalyzeDependenciesResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &AnalyzeDependenciesResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest PackageNameList
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest BadRequest
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest InternalServerError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 502:
		var dest BadGateway
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON502 = &dest

	}

	return response, nil
}

// ParseHealthCheckResponse parses an HTTP response from a HealthCheckWithResponse call
func ParseHealthCheckResponse(rsp *http.Response) (*HealthCheckResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &HealthCheckResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest string
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	}

	return response, nil
}

// ParseRetrieveDependenciesResponse parses an HTTP response from a RetrieveDependenciesWithResponse call
func ParseRetrieveDependenciesResponse(rsp *http.Response) (*RetrieveDependenciesResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &RetrieveDependenciesResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest PurlList
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest BadRequest
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest InternalServerError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 502:
		var dest BadGateway
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON502 = &dest

	}

	return response, nil
}

// ParseGetArtifactDependenciesResponse parses an HTTP response from a GetArtifactDependenciesWithResponse call
func ParseGetArtifactDependenciesResponse(rsp *http.Response) (*GetArtifactDependenciesResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetArtifactDependenciesResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest PurlList
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest BadRequest
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest InternalServerError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseGetArtifactVulnerabilitiesResponse parses an HTTP response from a GetArtifactVulnerabilitiesWithResponse call
func ParseGetArtifactVulnerabilitiesResponse(rsp *http.Response) (*GetArtifactVulnerabilitiesResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetArtifactVulnerabilitiesResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest VulnerabilityList
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest BadRequest
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest InternalServerError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseGetPackagePurlsByPurlResponse parses an HTTP response from a GetPackagePurlsByPurlWithResponse call
func ParseGetPackagePurlsByPurlResponse(rsp *http.Response) (*GetPackagePurlsByPurlResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetPackagePurlsByPurlResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest []string
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest BadRequest
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest InternalServerError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseGetPackageDependenciesByPurlResponse parses an HTTP response from a GetPackageDependenciesByPurlWithResponse call
func ParseGetPackageDependenciesByPurlResponse(rsp *http.Response) (*GetPackageDependenciesByPurlResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetPackageDependenciesByPurlResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest PurlList
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest BadRequest
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest InternalServerError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}

// ParseGetPackageVulnerabilitiesByPurlResponse parses an HTTP response from a GetPackageVulnerabilitiesByPurlWithResponse call
func ParseGetPackageVulnerabilitiesByPurlResponse(rsp *http.Response) (*GetPackageVulnerabilitiesByPurlResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &GetPackageVulnerabilitiesByPurlResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest VulnerabilityList
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON200 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 400:
		var dest BadRequest
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON400 = &dest

	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 500:
		var dest InternalServerError
		if err := json.Unmarshal(bodyBytes, &dest); err != nil {
			return nil, err
		}
		response.JSON500 = &dest

	}

	return response, nil
}
