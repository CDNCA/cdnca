package edgepublish

import (
	"context"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func validateL4AdditionalListenerTargets(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, nodeIDs []uuid.UUID, capabilities []*agentv1.Capability, now time.Time) error {
	var required []*agentv1.Capability
	for _, capability := range capabilities {
		if capability.ApiVersion >= 3 && (capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_TCP_PROXY || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_UDP_PROXY) {
			required = append(required, capability)
		}
	}
	if len(required) == 0 {
		return nil
	}
	advertised, err := loadSiteRuntimeV2TargetCapabilities(ctx, tx, scopeID, nodeIDs, now)
	if err != nil {
		return err
	}
	if err := validateSiteRuntimeV2TargetCapabilities(required, false, advertised, nil); err != nil {
		return readableTargetCapabilityError(ctx, tx, nodeIDs, required, advertised, err)
	}
	return nil
}
