package replication

import (
	"context"
	"database/sql"
	"encoding/json"
)

// Generation mirrors Python's own generation shape.
type Generation struct {
	GenerationNumber int64    `json:"generation_number"`
	CreatedAt        string   `json:"created_at"`
	SourceNodeID     string   `json:"source_node_id"`
	SchemaVersion    int      `json:"schema_version"`
	ContentHash      string   `json:"content_hash"`
	SectionKeys      []string `json:"section_keys"`
	Sections         Sections `json:"sections,omitempty"`
}

// CreateGeneration reads this node's own current replicable state and
// publishes it as a new, numbered, content-hashed generation --
// matching Python's own create_generation()/on_deploy_success() intent,
// but called explicitly (via the "Publish Generation" owner action)
// rather than automatically hooked into every deploy, since this Go
// control plane's own deploy pipeline (internal/dnsruntime) has no
// single "successful deploy" callback point equivalent to Python's
// alderpointdns_compiler.py deploy() this could hook without adding
// replication-specific coupling into that unrelated package.
func (s *Service) CreateGeneration(ctx context.Context) (Generation, error) {
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return Generation{}, err
	}
	sections, err := BuildPayload(ctx, s.DB)
	if err != nil {
		return Generation{}, err
	}
	hash, err := ContentHash(sections)
	if err != nil {
		return Generation{}, err
	}
	payloadJSON, err := json.Marshal(sections)
	if err != nil {
		return Generation{}, err
	}
	keysJSON, err := json.Marshal(sectionKeys(sections))
	if err != nil {
		return Generation{}, err
	}
	created := now()

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Generation{}, err
	}
	defer tx.Rollback()
	var maxNum sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(generation_number) FROM replication_generations`).Scan(&maxNum); err != nil {
		return Generation{}, err
	}
	next := maxNum.Int64 + 1
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO replication_generations (generation_number, created_at, source_node_id, schema_version, section_keys, content_hash, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		next, created, settings.NodeID, SchemaVersion, string(keysJSON), hash, string(payloadJSON),
	); err != nil {
		return Generation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Generation{}, err
	}
	return Generation{
		GenerationNumber: next, CreatedAt: created, SourceNodeID: settings.NodeID,
		SchemaVersion: SchemaVersion, ContentHash: hash, SectionKeys: sectionKeys(sections), Sections: sections,
	}, nil
}

// LatestGeneration returns the most recently published generation, or
// (nil, nil) if none has ever been published yet.
func (s *Service) LatestGeneration(ctx context.Context, includeSections bool) (*Generation, error) {
	row := s.DB.QueryRowContext(ctx, `
		SELECT generation_number, created_at, source_node_id, schema_version, section_keys, content_hash, payload
		FROM replication_generations ORDER BY generation_number DESC LIMIT 1`)
	var g Generation
	var keysJSON, payloadJSON string
	err := row.Scan(&g.GenerationNumber, &g.CreatedAt, &g.SourceNodeID, &g.SchemaVersion, &keysJSON, &g.ContentHash, &payloadJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(keysJSON), &g.SectionKeys)
	if includeSections {
		if err := json.Unmarshal([]byte(payloadJSON), &g.Sections); err != nil {
			return nil, err
		}
	}
	return &g, nil
}
