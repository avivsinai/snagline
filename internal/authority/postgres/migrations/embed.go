// Package migrations exposes the PostgreSQL authority schema to the runtime
// and integration harness without relying on a working-directory path.
package migrations

import "embed"

// FS contains ordered authority migrations.
//
//go:embed *.sql
var FS embed.FS
