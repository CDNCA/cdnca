package securityactivation

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// FailureReason is why a node failed the candidate (P11): the node's own
// failure text of its last failed deployment of the candidate's rollouts,
// e.g. "managed WAF unavailable: no waf engine module is installed".
type FailureReason struct {
	NodeID uuid.UUID `json:"node_id"`
	// NodeName / NodeIP name the node for the page (sec-ui-polish); IP is
	// its IPv4, else IPv6, else "".
	NodeName string `json:"node_name"`
	NodeIP   string `json:"node_ip"`
	Phase    string `json:"phase"`
	// Code is the protocol error code when the node sent one.
	Code string `json:"code,omitempty"`
	// Reason is a stable cause the page explains itself (FailureReason*
	// constants), "" when the text matches none.
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message"`
}

// FailureReasonWAFEngineUnavailable: the node has no managed WAF (CRS)
// engine module (agent dynwaf.ErrUnavailable "managed WAF unavailable").
const FailureReasonWAFEngineUnavailable = "waf_engine_unavailable"

// failureReason maps the node's failure text to a FailureReason* code. The
// agent's text (dynwaf.ErrUnavailable, possibly wrapped) is matched here so
// the page never parses English.
func failureReason(message string) string {
	if strings.Contains(strings.ToLower(message), "managed waf unavailable") {
		return FailureReasonWAFEngineUnavailable
	}
	return ""
}

const (
	maxFailureReasons       = 10
	maxFailureMessageLength = 512
)

// loadFailureReasons reads the failure of each node that failed one of the
// candidate's phase rollouts (latest attempt, latest failed transition).
// The text was already sanitized by the agent (control characters removed,
// at most 512 bytes); it is bounded again here.
func loadFailureReasons(ctx context.Context, tx pgx.Tx, candidateID uuid.UUID) ([]FailureReason, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (deployment.node_id) deployment.node_id,
		  COALESCE(node.name,''), COALESCE(host(COALESCE(node.ipv4,node.ipv6)),''), phase.phase, event.payload
		FROM security_policy_activation_rollouts phase
		JOIN node_deployments deployment ON deployment.rollout_id=phase.rollout_id
		LEFT JOIN nodes node ON node.id=deployment.node_id
		JOIN deployment_status_events event ON event.deployment_id=deployment.id AND event.attempt=deployment.attempt
		WHERE phase.candidate_id=$1 AND event.state IN ('failed','rollback_failed')
		  AND NOT `+edgedeployment.SupersededDeploymentSQL+`
		ORDER BY deployment.node_id, deployment.attempt DESC, event.transition_sequence DESC
		LIMIT $2`, candidateID, maxFailureReasons)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	reasons := []FailureReason{}
	for rows.Next() {
		var reason FailureReason
		var payload []byte
		if err := rows.Scan(&reason.NodeID, &reason.NodeName, &reason.NodeIP, &reason.Phase, &payload); err != nil {
			return nil, err
		}
		reason.Code, reason.Message = deploymentFailure(payload)
		reason.Reason = failureReason(reason.Message)
		reasons = append(reasons, reason)
	}
	return reasons, rows.Err()
}

// deploymentFailure is the error code and text of a failed DeploymentStatus:
// the protocol error's message, else the failed check's summary.
func deploymentFailure(payload []byte) (string, string) {
	status := new(agentv1.DeploymentStatus)
	if len(payload) == 0 || proto.Unmarshal(payload, status) != nil {
		return "", ""
	}
	var code, message string
	if status.Error != nil {
		code, message = status.Error.Code.String(), status.Error.Message
	}
	if message == "" {
		for _, check := range status.Checks {
			if check != nil && !check.Succeeded && check.Summary != "" {
				message = check.Summary
				break
			}
		}
	}
	return code, boundedText(message)
}

func boundedText(value string) string {
	value = strings.Join(strings.Fields(strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)), " ")
	if len(value) <= maxFailureMessageLength {
		return value
	}
	value = value[:maxFailureMessageLength]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}
