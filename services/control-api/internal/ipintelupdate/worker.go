package ipintelupdate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel/builder"
	"github.com/jackc/pgx/v5"
)

var errSnapshotOlder = errors.New("ip intel snapshot is not newer than the local library")

// Run checks every minute (or when woken) whether a pull is due and runs it
// on the instance that takes the lease. Returns when ctx ends.
func (service *Service) Run(ctx context.Context) error {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		if _, err := service.PullOnce(ctx, false); err != nil && ctx.Err() == nil {
			service.config.Logger.Warn("ip intel update pull", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-service.wake:
		}
	}
}

// PullOnce runs one pull when due (force: regardless of schedule, still
// respecting the lease). Due = enabled, the lease grants the module, and an
// operator asked or next_check_at is empty or reached. The returned error is
// for bookkeeping failures only; a failed pull is in the result and state.
func (service *Service) PullOnce(ctx context.Context, force bool) (PullResult, error) {
	now := service.now()
	var settings stored
	claimed := false
	err := pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		var err error
		if settings, err = readSettings(ctx, tx, false); err != nil || !settings.Enabled {
			return err
		}
		licensed, err := service.licensed(ctx, tx)
		if err != nil || !licensed {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE ip_intel_update_state SET running_until=$2,check_requested_at=NULL,updated_at=$1
			WHERE singleton AND (running_until IS NULL OR running_until<=$1)
			AND ($3 OR check_requested_at IS NOT NULL OR next_check_at IS NULL OR next_check_at<=$1)`,
			now, now.Add(pullTimeout+5*time.Minute), force)
		claimed = err == nil && tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		return PullResult{}, fmt.Errorf("claim ip intel update pull: %w", err)
	}
	if !claimed {
		return PullResult{}, nil
	}
	result, retry, pullErr := service.pull(ctx, settings, now)
	result.Ran = true
	finished := service.now()
	zone, _ := validSchedule(settings.IntervalMinutes, settings.AnchorMinute, settings.TimeZone)
	next := NextPull(finished, settings.IntervalMinutes, settings.AnchorMinute, zone)
	if pullErr != nil {
		if result.Outcome == OutcomePending {
			retry = max(retry, time.Minute)
		} else {
			retry = max(retry, retryAfter)
		}
		if finished.Add(retry).Before(next) {
			next = finished.Add(retry)
		}
		service.config.Logger.Warn("ip intel update pull failed", "error_code", result.ErrorCode, "error", errorText(pullErr))
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	err = pgx.BeginFunc(recordCtx, service.config.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(recordCtx, `UPDATE ip_intel_update_state SET last_checked_at=$1,
			last_success_at=CASE WHEN $2 IN ('not_modified','published','unchanged') THEN $1 ELSE last_success_at END,
			last_outcome=$2,last_release=CASE WHEN $3<>'' THEN $3 ELSE last_release END,last_http_status=$4,
			last_error_code=$5,last_error=$6,next_check_at=$7,running_until=NULL,updated_at=$1 WHERE singleton`,
			finished, result.Outcome, result.Release, result.HTTPStatus, result.ErrorCode, errorText(pullErr), next); err != nil {
			return err
		}
		outcome := "success"
		if pullErr != nil {
			outcome = "failure"
		}
		return service.appendAudit(recordCtx, tx, nil, ActionPull, outcome, map[string]any{"outcome": result.Outcome,
			"release": result.Release, "revision": result.Revision, "http_status": result.HTTPStatus, "error_code": result.ErrorCode})
	})
	if err != nil {
		return result, fmt.Errorf("record ip intel update pull: %w", err)
	}
	if result.Outcome == OutcomePublished && service.config.OnPublished != nil {
		service.config.OnPublished()
	}
	return result, nil
}

// pull downloads the snapshot (If-None-Match: the local library's release),
// builds and stores a newer local library.
func (service *Service) pull(ctx context.Context, settings stored, now time.Time) (PullResult, time.Duration, error) {
	result := PullResult{}
	fail := func(err error) (PullResult, time.Duration, error) {
		result.Outcome, result.ErrorCode = OutcomeFailed, errorCode(err)
		if errors.Is(err, builder.ErrSourcePending) {
			result.Outcome = OutcomePending
		}
		return result, 0, err
	}
	if settings.KeyID == nil {
		return fail(ErrDisabled)
	}
	secret, err := service.open(*settings.KeyID, settings.Ciphertext)
	if err != nil {
		return fail(err)
	}
	source, err := builder.NewHTTPSource(builder.HTTPSourceConfig{URL: settings.URL, APIKey: settings.APIKey, APISecret: secret,
		Timeout: pullTimeout, MaxBytes: service.config.MaxBytes})
	if err != nil {
		return fail(fmt.Errorf("%w: %v", ErrInvalidInput, err))
	}
	known, knownUpdated, err := service.localLibrary(ctx)
	if err != nil {
		return fail(err)
	}
	fetched, err := source.Fetch(ctx, known)
	result.HTTPStatus, result.Release = fetched.Status, fetched.Release
	if err != nil {
		outcome, _, failed := fail(err)
		return outcome, fetched.RetryAfter, failed
	}
	if fetched.NotModified {
		result.Outcome = OutcomeNotModified
		return result, 0, nil
	}
	// Only newer data replaces the local library (several dnspup instances
	// may briefly serve different releases).
	if !knownUpdated.IsZero() && !fetched.Collection.DataUpdatedAt.After(knownUpdated) {
		if fetched.Collection.SourceRelease == known || fetched.Collection.DataUpdatedAt.Equal(knownUpdated) {
			result.Outcome = OutcomeUnchanged
			return result, 0, nil
		}
		return fail(fmt.Errorf("%w: snapshot %s data %s, local library data %s", errSnapshotOlder, fetched.Release,
			fetched.Collection.DataUpdatedAt.Format(time.RFC3339), knownUpdated.Format(time.RFC3339)))
	}
	latest, err := service.config.Publisher.LatestLocalRevision(ctx)
	if err != nil {
		return fail(err)
	}
	revision := latest + 1
	buildID := fmt.Sprintf("ipintel-local-%s-%06d", now.Format("20060102"), revision)
	artifact, err := builder.Compile(fetched.Collection, builder.CompileRequest{Revision: revision, BuildID: buildID, GeneratedAt: now})
	if err != nil {
		return fail(err)
	}
	entry := artifactcatalog.Entry{ArtifactID: localArtifactID, Kind: artifactcatalog.KindIPIntel, MediaType: artifactcatalog.MediaTypeIPIntel,
		Version: buildID, Revision: revision, SHA256: artifact.SHA256, Size: int64(len(artifact.Bytes)),
		RequiresFeature: Feature, Encryption: artifactcatalog.EncryptionNone,
		RequiresCapability: &artifactcatalog.Capability{Name: ipintel.Capability, MinVersion: artifact.Metadata.CapabilityVersion}}
	err = pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		// The module may have been revoked during the download.
		licensed, err := service.licensed(ctx, tx)
		if err != nil {
			return err
		}
		if !licensed {
			return ErrFeatureDenied
		}
		return service.config.Publisher.StoreLocalBuildTx(ctx, tx, entry, artifact.Bytes, map[string]any{
			"source": "dnspup", "source_release": fetched.Collection.SourceRelease, "release": fetched.Release,
			"data_updated_at": artifact.Metadata.DataUpdatedAt, "download_sha256": fetched.SHA256})
	})
	if err != nil {
		return fail(err)
	}
	result.Outcome, result.Revision = OutcomePublished, revision
	return result, 0, nil
}

const localArtifactID = "ipintel/local"

// localLibrary is the source release and data time of ipintel/local.
func (service *Service) localLibrary(ctx context.Context) (string, time.Time, error) {
	var content []byte
	err := service.config.Pool.QueryRow(ctx, `SELECT object.content FROM local_artifacts local
		JOIN artifact_objects object ON object.sha256=local.current_sha256 WHERE local.artifact_id=$1`, localArtifactID).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read local ip intel library: %w", err)
	}
	table, err := ipintel.Open(content)
	if err != nil {
		return "", time.Time{}, nil // rebuild over a library that no longer opens
	}
	updated, _ := time.Parse(time.RFC3339, table.Metadata.DataUpdatedAt)
	return table.Metadata.SourceRelease, updated, nil
}
