package migrations

import "embed"

// FS contains the versioned control-api database migrations.
//
//go:embed *.sql
var FS embed.FS
