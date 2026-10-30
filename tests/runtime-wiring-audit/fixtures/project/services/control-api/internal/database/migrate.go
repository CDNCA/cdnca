package database

import (
	"context"

	"fixture/services/control-api/migrations"
)

func Migrate(context.Context, any, string) error {
	_ = migrations.FS
	return nil
}

func migrationSource() any { return migrations.FS }
