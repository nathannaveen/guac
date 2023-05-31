// Code generated by MockGen. DO NOT EDIT.
// Source: /Users/nathannaveen/go/src/github.com/nathannaveen/guac/pkg/ingestor/parser/common/types.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	assembler "github.com/guacsec/guac/pkg/assembler"
	processor "github.com/guacsec/guac/pkg/handler/processor"
	common "github.com/guacsec/guac/pkg/ingestor/parser/common"
)

// MockDocumentParser is a mock of DocumentParser interface.
type MockDocumentParser struct {
	ctrl     *gomock.Controller
	recorder *MockDocumentParserMockRecorder
}

// MockDocumentParserMockRecorder is the mock recorder for MockDocumentParser.
type MockDocumentParserMockRecorder struct {
	mock *MockDocumentParser
}

// NewMockDocumentParser creates a new mock instance.
func NewMockDocumentParser(ctrl *gomock.Controller) *MockDocumentParser {
	mock := &MockDocumentParser{ctrl: ctrl}
	mock.recorder = &MockDocumentParserMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDocumentParser) EXPECT() *MockDocumentParserMockRecorder {
	return m.recorder
}

// GetIdentifiers mocks base method.
func (m *MockDocumentParser) GetIdentifiers(ctx context.Context) (*common.IdentifierStrings, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIdentifiers", ctx)
	ret0, _ := ret[0].(*common.IdentifierStrings)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIdentifiers indicates an expected call of GetIdentifiers.
func (mr *MockDocumentParserMockRecorder) GetIdentifiers(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIdentifiers", reflect.TypeOf((*MockDocumentParser)(nil).GetIdentifiers), ctx)
}

// GetIdentities mocks base method.
func (m *MockDocumentParser) GetIdentities(ctx context.Context) []common.TrustInformation {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetIdentities", ctx)
	ret0, _ := ret[0].([]common.TrustInformation)
	return ret0
}

// GetIdentities indicates an expected call of GetIdentities.
func (mr *MockDocumentParserMockRecorder) GetIdentities(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIdentities", reflect.TypeOf((*MockDocumentParser)(nil).GetIdentities), ctx)
}

// GetPredicates mocks base method.
func (m *MockDocumentParser) GetPredicates(ctx context.Context) *assembler.IngestPredicates {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPredicates", ctx)
	ret0, _ := ret[0].(*assembler.IngestPredicates)
	return ret0
}

// GetPredicates indicates an expected call of GetPredicates.
func (mr *MockDocumentParserMockRecorder) GetPredicates(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPredicates", reflect.TypeOf((*MockDocumentParser)(nil).GetPredicates), ctx)
}

// Parse mocks base method.
func (m *MockDocumentParser) Parse(ctx context.Context, doc *processor.Document) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Parse", ctx, doc)
	ret0, _ := ret[0].(error)
	return ret0
}

// Parse indicates an expected call of Parse.
func (mr *MockDocumentParserMockRecorder) Parse(ctx, doc interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Parse", reflect.TypeOf((*MockDocumentParser)(nil).Parse), ctx, doc)
}
