package sqlstore

import (
	"embed"
)

// CreateTableFiles embeds all SQL schema files (table creation)
//
//go:embed *.sql
var CreateTableFiles embed.FS

// MigrationFiles embeds all SQL migration files from migrations/ subdirectory
// These are incremental changes to existing tables (ALTER, new columns, etc.)
//
//go:embed migrations/*.sql
var MigrationFiles embed.FS
