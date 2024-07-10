// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/artifact"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/occurrence"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/packageversion"
	"github.com/guacsec/guac/pkg/assembler/backends/ent/sourcename"
)

// Occurrence is the model entity for the Occurrence schema.
type Occurrence struct {
	config `json:"-"`
	// ID of the ent.
	ID uuid.UUID `json:"id,omitempty"`
	// The artifact in the relationship
	ArtifactID uuid.UUID `json:"artifact_id,omitempty"`
	// Justification for the attested relationship
	Justification string `json:"justification,omitempty"`
	// Document from which this attestation is generated from
	Origin string `json:"origin,omitempty"`
	// GUAC collector for the document
	Collector string `json:"collector,omitempty"`
	// DocumentRef holds the value of the "document_ref" field.
	DocumentRef string `json:"document_ref,omitempty"`
	// SourceID holds the value of the "source_id" field.
	SourceID *uuid.UUID `json:"source_id,omitempty"`
	// PackageID holds the value of the "package_id" field.
	PackageID *uuid.UUID `json:"package_id,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the OccurrenceQuery when eager-loading is set.
	Edges        OccurrenceEdges `json:"edges"`
	selectValues sql.SelectValues
}

// OccurrenceEdges holds the relations/edges for other nodes in the graph.
type OccurrenceEdges struct {
	// Artifact holds the value of the artifact edge.
	Artifact *Artifact `json:"artifact,omitempty"`
	// Package holds the value of the package edge.
	Package *PackageVersion `json:"package,omitempty"`
	// Source holds the value of the source edge.
	Source *SourceName `json:"source,omitempty"`
	// IncludedInSboms holds the value of the included_in_sboms edge.
	IncludedInSboms []*BillOfMaterials `json:"included_in_sboms,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [4]bool
	// totalCount holds the count of the edges above.
	totalCount [4]map[string]int

	namedIncludedInSboms map[string][]*BillOfMaterials
}

// ArtifactOrErr returns the Artifact value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e OccurrenceEdges) ArtifactOrErr() (*Artifact, error) {
	if e.Artifact != nil {
		return e.Artifact, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: artifact.Label}
	}
	return nil, &NotLoadedError{edge: "artifact"}
}

// PackageOrErr returns the Package value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e OccurrenceEdges) PackageOrErr() (*PackageVersion, error) {
	if e.Package != nil {
		return e.Package, nil
	} else if e.loadedTypes[1] {
		return nil, &NotFoundError{label: packageversion.Label}
	}
	return nil, &NotLoadedError{edge: "package"}
}

// SourceOrErr returns the Source value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e OccurrenceEdges) SourceOrErr() (*SourceName, error) {
	if e.Source != nil {
		return e.Source, nil
	} else if e.loadedTypes[2] {
		return nil, &NotFoundError{label: sourcename.Label}
	}
	return nil, &NotLoadedError{edge: "source"}
}

// IncludedInSbomsOrErr returns the IncludedInSboms value or an error if the edge
// was not loaded in eager-loading.
func (e OccurrenceEdges) IncludedInSbomsOrErr() ([]*BillOfMaterials, error) {
	if e.loadedTypes[3] {
		return e.IncludedInSboms, nil
	}
	return nil, &NotLoadedError{edge: "included_in_sboms"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Occurrence) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case occurrence.FieldSourceID, occurrence.FieldPackageID:
			values[i] = &sql.NullScanner{S: new(uuid.UUID)}
		case occurrence.FieldJustification, occurrence.FieldOrigin, occurrence.FieldCollector, occurrence.FieldDocumentRef:
			values[i] = new(sql.NullString)
		case occurrence.FieldID, occurrence.FieldArtifactID:
			values[i] = new(uuid.UUID)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Occurrence fields.
func (o *Occurrence) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case occurrence.FieldID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field id", values[i])
			} else if value != nil {
				o.ID = *value
			}
		case occurrence.FieldArtifactID:
			if value, ok := values[i].(*uuid.UUID); !ok {
				return fmt.Errorf("unexpected type %T for field artifact_id", values[i])
			} else if value != nil {
				o.ArtifactID = *value
			}
		case occurrence.FieldJustification:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field justification", values[i])
			} else if value.Valid {
				o.Justification = value.String
			}
		case occurrence.FieldOrigin:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field origin", values[i])
			} else if value.Valid {
				o.Origin = value.String
			}
		case occurrence.FieldCollector:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field collector", values[i])
			} else if value.Valid {
				o.Collector = value.String
			}
		case occurrence.FieldDocumentRef:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field document_ref", values[i])
			} else if value.Valid {
				o.DocumentRef = value.String
			}
		case occurrence.FieldSourceID:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field source_id", values[i])
			} else if value.Valid {
				o.SourceID = new(uuid.UUID)
				*o.SourceID = *value.S.(*uuid.UUID)
			}
		case occurrence.FieldPackageID:
			if value, ok := values[i].(*sql.NullScanner); !ok {
				return fmt.Errorf("unexpected type %T for field package_id", values[i])
			} else if value.Valid {
				o.PackageID = new(uuid.UUID)
				*o.PackageID = *value.S.(*uuid.UUID)
			}
		default:
			o.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the Occurrence.
// This includes values selected through modifiers, order, etc.
func (o *Occurrence) Value(name string) (ent.Value, error) {
	return o.selectValues.Get(name)
}

// QueryArtifact queries the "artifact" edge of the Occurrence entity.
func (o *Occurrence) QueryArtifact() *ArtifactQuery {
	return NewOccurrenceClient(o.config).QueryArtifact(o)
}

// QueryPackage queries the "package" edge of the Occurrence entity.
func (o *Occurrence) QueryPackage() *PackageVersionQuery {
	return NewOccurrenceClient(o.config).QueryPackage(o)
}

// QuerySource queries the "source" edge of the Occurrence entity.
func (o *Occurrence) QuerySource() *SourceNameQuery {
	return NewOccurrenceClient(o.config).QuerySource(o)
}

// QueryIncludedInSboms queries the "included_in_sboms" edge of the Occurrence entity.
func (o *Occurrence) QueryIncludedInSboms() *BillOfMaterialsQuery {
	return NewOccurrenceClient(o.config).QueryIncludedInSboms(o)
}

// Update returns a builder for updating this Occurrence.
// Note that you need to call Occurrence.Unwrap() before calling this method if this Occurrence
// was returned from a transaction, and the transaction was committed or rolled back.
func (o *Occurrence) Update() *OccurrenceUpdateOne {
	return NewOccurrenceClient(o.config).UpdateOne(o)
}

// Unwrap unwraps the Occurrence entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (o *Occurrence) Unwrap() *Occurrence {
	_tx, ok := o.config.driver.(*txDriver)
	if !ok {
		panic("ent: Occurrence is not a transactional entity")
	}
	o.config.driver = _tx.drv
	return o
}

// String implements the fmt.Stringer.
func (o *Occurrence) String() string {
	var builder strings.Builder
	builder.WriteString("Occurrence(")
	builder.WriteString(fmt.Sprintf("id=%v, ", o.ID))
	builder.WriteString("artifact_id=")
	builder.WriteString(fmt.Sprintf("%v", o.ArtifactID))
	builder.WriteString(", ")
	builder.WriteString("justification=")
	builder.WriteString(o.Justification)
	builder.WriteString(", ")
	builder.WriteString("origin=")
	builder.WriteString(o.Origin)
	builder.WriteString(", ")
	builder.WriteString("collector=")
	builder.WriteString(o.Collector)
	builder.WriteString(", ")
	builder.WriteString("document_ref=")
	builder.WriteString(o.DocumentRef)
	builder.WriteString(", ")
	if v := o.SourceID; v != nil {
		builder.WriteString("source_id=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteString(", ")
	if v := o.PackageID; v != nil {
		builder.WriteString("package_id=")
		builder.WriteString(fmt.Sprintf("%v", *v))
	}
	builder.WriteByte(')')
	return builder.String()
}

// NamedIncludedInSboms returns the IncludedInSboms named value or an error if the edge was not
// loaded in eager-loading with this name.
func (o *Occurrence) NamedIncludedInSboms(name string) ([]*BillOfMaterials, error) {
	if o.Edges.namedIncludedInSboms == nil {
		return nil, &NotLoadedError{edge: name}
	}
	nodes, ok := o.Edges.namedIncludedInSboms[name]
	if !ok {
		return nil, &NotLoadedError{edge: name}
	}
	return nodes, nil
}

func (o *Occurrence) appendNamedIncludedInSboms(name string, edges ...*BillOfMaterials) {
	if o.Edges.namedIncludedInSboms == nil {
		o.Edges.namedIncludedInSboms = make(map[string][]*BillOfMaterials)
	}
	if len(edges) == 0 {
		o.Edges.namedIncludedInSboms[name] = []*BillOfMaterials{}
	} else {
		o.Edges.namedIncludedInSboms[name] = append(o.Edges.namedIncludedInSboms[name], edges...)
	}
}

// Occurrences is a parsable slice of Occurrence.
type Occurrences []*Occurrence
