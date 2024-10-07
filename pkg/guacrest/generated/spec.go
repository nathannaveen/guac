// Package generated provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.1-0.20240823215434-d232e9efa9f5 DO NOT EDIT.
package generated

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
	"AAA=",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
