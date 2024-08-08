// Package client provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/deepmap/oapi-codegen/v2 version v2.1.0 DO NOT EDIT.
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

	// FindLatestSBOM request
	FindLatestSBOM(ctx context.Context, params *FindLatestSBOMParams, reqEditors ...RequestEditorFn) (*http.Response, error)

	// FindVulnerabilitiesInSBOM request
	FindVulnerabilitiesInSBOM(ctx context.Context, params *FindVulnerabilitiesInSBOMParams, reqEditors ...RequestEditorFn) (*http.Response, error)
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

func (c *Client) FindLatestSBOM(ctx context.Context, params *FindLatestSBOMParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewFindLatestSBOMRequest(c.Server, params)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	if err := c.applyEditors(ctx, req, reqEditors); err != nil {
		return nil, err
	}
	return c.Client.Do(req)
}

func (c *Client) FindVulnerabilitiesInSBOM(ctx context.Context, params *FindVulnerabilitiesInSBOMParams, reqEditors ...RequestEditorFn) (*http.Response, error) {
	req, err := NewFindVulnerabilitiesInSBOMRequest(c.Server, params)
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

// NewFindLatestSBOMRequest generates requests for FindLatestSBOM
func NewFindLatestSBOMRequest(server string, params *FindLatestSBOMParams) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/query/latest-sbom")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "pkgID", runtime.ParamLocationQuery, params.PkgID); err != nil {
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

// NewFindVulnerabilitiesInSBOMRequest generates requests for FindVulnerabilitiesInSBOM
func NewFindVulnerabilitiesInSBOMRequest(server string, params *FindVulnerabilitiesInSBOMParams) (*http.Request, error) {
	var err error

	serverURL, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	operationPath := fmt.Sprintf("/query/vulnerabilities-in-sbom")
	if operationPath[0] == '/' {
		operationPath = "." + operationPath
	}

	queryURL, err := serverURL.Parse(operationPath)
	if err != nil {
		return nil, err
	}

	if params != nil {
		queryValues := queryURL.Query()

		if queryFrag, err := runtime.StyleParamWithLocation("form", true, "pkgID", runtime.ParamLocationQuery, params.PkgID); err != nil {
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

	// FindLatestSBOMWithResponse request
	FindLatestSBOMWithResponse(ctx context.Context, params *FindLatestSBOMParams, reqEditors ...RequestEditorFn) (*FindLatestSBOMResponse, error)

	// FindVulnerabilitiesInSBOMWithResponse request
	FindVulnerabilitiesInSBOMWithResponse(ctx context.Context, params *FindVulnerabilitiesInSBOMParams, reqEditors ...RequestEditorFn) (*FindVulnerabilitiesInSBOMResponse, error)
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

type FindLatestSBOMResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *HasSBOM
	JSON400      *BadRequest
	JSON500      *InternalServerError
	JSON502      *BadGateway
}

// Status returns HTTPResponse.Status
func (r FindLatestSBOMResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r FindLatestSBOMResponse) StatusCode() int {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.StatusCode
	}
	return 0
}

type FindVulnerabilitiesInSBOMResponse struct {
	Body         []byte
	HTTPResponse *http.Response
	JSON200      *[]VulnerabilityIDs
	JSON400      *BadRequest
	JSON500      *InternalServerError
	JSON502      *BadGateway
}

// Status returns HTTPResponse.Status
func (r FindVulnerabilitiesInSBOMResponse) Status() string {
	if r.HTTPResponse != nil {
		return r.HTTPResponse.Status
	}
	return http.StatusText(0)
}

// StatusCode returns HTTPResponse.StatusCode
func (r FindVulnerabilitiesInSBOMResponse) StatusCode() int {
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

// FindLatestSBOMWithResponse request returning *FindLatestSBOMResponse
func (c *ClientWithResponses) FindLatestSBOMWithResponse(ctx context.Context, params *FindLatestSBOMParams, reqEditors ...RequestEditorFn) (*FindLatestSBOMResponse, error) {
	rsp, err := c.FindLatestSBOM(ctx, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseFindLatestSBOMResponse(rsp)
}

// FindVulnerabilitiesInSBOMWithResponse request returning *FindVulnerabilitiesInSBOMResponse
func (c *ClientWithResponses) FindVulnerabilitiesInSBOMWithResponse(ctx context.Context, params *FindVulnerabilitiesInSBOMParams, reqEditors ...RequestEditorFn) (*FindVulnerabilitiesInSBOMResponse, error) {
	rsp, err := c.FindVulnerabilitiesInSBOM(ctx, params, reqEditors...)
	if err != nil {
		return nil, err
	}
	return ParseFindVulnerabilitiesInSBOMResponse(rsp)
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

// ParseFindLatestSBOMResponse parses an HTTP response from a FindLatestSBOMWithResponse call
func ParseFindLatestSBOMResponse(rsp *http.Response) (*FindLatestSBOMResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &FindLatestSBOMResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest HasSBOM
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

// ParseFindVulnerabilitiesInSBOMResponse parses an HTTP response from a FindVulnerabilitiesInSBOMWithResponse call
func ParseFindVulnerabilitiesInSBOMResponse(rsp *http.Response) (*FindVulnerabilitiesInSBOMResponse, error) {
	bodyBytes, err := io.ReadAll(rsp.Body)
	defer func() { _ = rsp.Body.Close() }()
	if err != nil {
		return nil, err
	}

	response := &FindVulnerabilitiesInSBOMResponse{
		Body:         bodyBytes,
		HTTPResponse: rsp,
	}

	switch {
	case strings.Contains(rsp.Header.Get("Content-Type"), "json") && rsp.StatusCode == 200:
		var dest []VulnerabilityIDs
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
