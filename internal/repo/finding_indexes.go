package repo

import (
	"context"
	"fmt"
)

// initFindingIndexes indexes the two JSON fields that every task report filters on.
// They must be created after migrateFindings, which can rebuild the table.
func (s *RuntimeStore) initFindingIndexes(ctx context.Context) error {
	for _, statement := range []string{
		`CREATE INDEX IF NOT EXISTS findings_status ON security_findings(json_extract(data,'$.status'))`,
		`CREATE INDEX IF NOT EXISTS findings_target ON security_findings(json_extract(data,'$.target'))`,
	} {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize finding indexes: %w", err)
		}
	}
	return nil
}
