package edgepublish

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func loadTelemetryInstallationID(ctx context.Context, tx pgx.Tx) (uuid.UUID, error) {
	var raw string
	if err := tx.QueryRow(ctx, `SELECT installation_id FROM control_installation_entitlement WHERE singleton`).Scan(&raw); err != nil {
		return uuid.Nil, fmt.Errorf("%w: load telemetry installation identity", ErrPersistence)
	}
	installationID, err := uuid.Parse(raw)
	if err != nil || installationID == uuid.Nil || installationID.String() != raw {
		return uuid.Nil, fmt.Errorf("%w: invalid telemetry installation identity", ErrPersistence)
	}
	return installationID, nil
}
