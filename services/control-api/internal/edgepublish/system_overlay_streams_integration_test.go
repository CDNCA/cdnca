//go:build integration

// 待出包前全量跑（子任务只写不跑 PG 集成）。
package edgepublish

import (
	"bytes"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 租户有未发布的编辑（manual 草稿）时，系统重新发布走停用叠加。
// 超额停服的转发被叠加去掉；恢复后同样走系统重新发布，叠加按最近一次带它的发布
// 放回，不等租户下次发布，也不带草稿。
func TestSystemRepublishStopOverlayRestoresRecoveredForward(t *testing.T) {
	fixture := newPublishFixture(t)
	site := fixture.createSite(t, "overlay-l4.example", 8081, false).Site
	stream := fixture.createStream(t, "overlay-l4", 19100, "198.51.100.41", 9100).Forward
	key := seedV2DefaultNode(t, fixture, fixture.nodeID)
	base, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "overlay-l4-base", fixture.nodeID,
		siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	finishPublishDeployment(t, fixture, base, &base.ConfigVersionID, nil)
	republisher, err := NewSystemRepublisher(fixture.service, SystemRepublisherConfig{WorkerID: "syspub-l4", LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	scope := &SystemRepublishScope{Pool: fixture.pool, ScopeID: fixture.scopeID, UserID: fixture.userID,
		SiteID: site.ID, fixture: fixture, republisher: republisher}
	// 草稿：网站回源改动，叠加不能带出去。
	scope.EditSiteOrigin(t, site.ID, "203.0.113.199")

	trafficStop(t, scope, stream.ID, true)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != SystemOutcomePublished {
		t.Fatalf("stop overlay: %+v", attempt)
	}
	if streams := releasedStreams(t, fixture, key); len(streams) != 0 {
		t.Fatalf("stopped forward still released: %+v", streams)
	}

	scope.SettleDeployments(t)
	trafficStop(t, scope, stream.ID, false)
	scope.Run(t)
	if attempt := scope.LatestAttempt(t); attempt.Outcome != SystemOutcomePublished {
		errorClass := ""
		if attempt.ErrorClass != nil {
			errorClass = *attempt.ErrorClass
		}
		t.Fatalf("restore overlay: %+v error_class=%q", attempt, errorClass)
	}
	streams := releasedStreams(t, fixture, key)
	if len(streams) != 1 || streams[0].StreamID != stream.ID.String() || streams[0].Listener.Port != 19100 ||
		streams[0].PackageSubscriptionID != fixture.subscriptionID.String() {
		t.Fatalf("restored forward = %+v", streams)
	}
	if document := decodeReceivedV2Document(t, latestReceivedBundle(t, fixture, key)); len(document.Sites) != 1 ||
		document.Sites[0].ID != site.ID.String() {
		t.Fatalf("restore overlay sites = %+v", document.Sites)
	}
	if plaintext := openLatestNodeArtifact(t, fixture, key); bytesContains(plaintext, "203.0.113.199") {
		t.Fatal("restore overlay carries the site draft")
	}
}

// trafficStop stops (stop=true) or restores forwardID the way the package
// traffic enforcement does (493 fact + admin_status), under the scope lock,
// and queues the traffic enforcement republication.
func trafficStop(t *testing.T, scope *SystemRepublishScope, forwardID uuid.UUID, stop bool) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		var from int64
		if err := tx.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
			scope.ScopeID).Scan(&from); err != nil {
			return err
		}
		status := "normal"
		if stop {
			status = "traffic_exceeded"
			if _, err := tx.Exec(t.Context(), `INSERT INTO package_traffic_stream_suspensions(
				suspension_id,tenant_scope_id,subscription_id,stream_id,period_key,head_revision,suspended_at)
				VALUES($1,$2,$3,$4,'2026-09',1,clock_timestamp())`, uuid.New(), scope.ScopeID, scope.fixture.subscriptionID,
				forwardID); err != nil {
				return err
			}
		} else if _, err := tx.Exec(t.Context(), `UPDATE package_traffic_stream_suspensions
			SET recovered_at=clock_timestamp(),recovered_period_key='2026-10',recovered_reason='new_cycle',recovered_stream_status='normal'
			WHERE stream_id=$1 AND recovered_at IS NULL`, forwardID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE l4_forwards SET admin_status=$2 WHERE id=$1`, forwardID, status); err != nil {
			return err
		}
		if err := RecordSystemRevisionSegmentTx(t.Context(), tx, scope.ScopeID, from, SystemTriggerTrafficEnforcement); err != nil {
			return err
		}
		return RequestSystemRepublicationTx(t.Context(), tx, SystemRepublicationRequest{ScopeID: scope.ScopeID,
			Trigger: SystemTriggerTrafficEnforcement})
	}); err != nil {
		t.Fatal(err)
	}
}

func releasedStreams(t *testing.T, fixture *publishFixture, key []byte) []edgeconfig.L4StreamRuntimeV2 {
	t.Helper()
	document := decodeReceivedV2Document(t, latestReceivedBundle(t, fixture, key))
	if document.Streams == nil {
		return nil
	}
	return document.Streams.StreamsV2
}

// latestReceivedBundle opens the latest publication's release for the
// fixture node, as the node does.
func latestReceivedBundle(t *testing.T, fixture *publishFixture, key []byte) edgeconfig.Bundle {
	t.Helper()
	var deploymentID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT deployment.id
		FROM edge_config_publications publication
		JOIN node_deployments deployment ON deployment.rollout_id=publication.rollout_id AND deployment.node_id=$2
		WHERE publication.configuration_scope_id=$1 ORDER BY publication.source_revision DESC LIMIT 1`,
		fixture.scopeID, fixture.nodeID).Scan(&deploymentID); err != nil {
		t.Fatal(err)
	}
	release, err := OpenSiteObjectReleaseForTest(t.Context(), fixture.pool, deploymentID, key)
	if err != nil {
		t.Fatalf("node release: %v", err)
	}
	return release.Bundle
}

func bytesContains(value []byte, text string) bool { return bytes.Contains(value, []byte(text)) }
