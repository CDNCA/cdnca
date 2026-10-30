package systemconfig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	CategoryNginx           = "nginx"
	CategoryDefaults        = "defaults"
	CategoryResources       = "resources"
	CategoryErrorPages      = "error_pages"
	CategorySecrets         = "secrets"
	CategoryNodeMonitoring  = "node_monitoring"
	CategoryDDoSProtection  = "ddos_protection"
	CategoryAccessLogFields = "access_log_fields"

	SecretIntentReplace = "replace"
	SecretIntentClear   = "clear"
)

var ErrEntitlementDenied = errors.New("system configuration entitlement denied")

// ErrPendingCategoriesChanged reports that the categories a revision would
// make effective differ from what the caller confirmed.
var ErrPendingCategoriesChanged = errors.New("system configuration pending categories changed")

var categoryCatalog = []string{
	CategoryNginx,
	CategoryDefaults,
	CategoryResources,
	CategoryErrorPages,
	CategorySecrets,
	CategoryNodeMonitoring,
	CategoryDDoSProtection,
	CategoryAccessLogFields,
}

type SecretChange struct {
	Intent      string                   `json:"intent"`
	Replacement *SecretEnvelopeReference `json:"replacement,omitempty"`
}

type CategoryChange struct {
	Nginx           *NginxLimits                 `json:"nginx,omitempty"`
	Defaults        *DefaultReferences           `json:"defaults,omitempty"`
	Resources       *ResourceLimits              `json:"resources,omitempty"`
	ErrorPages      *[]ErrorPageMetadata         `json:"error_pages,omitempty"`
	Secret          *SecretChange                `json:"secrets,omitempty"`
	NodeMonitoring  *NodeMonitoringConfiguration `json:"node_monitoring,omitempty"`
	DDoSProtection  *edgeconfig.DDoSProtection   `json:"ddos_protection,omitempty"`
	AccessLogFields *edgeconfig.AccessLogFields  `json:"access_log_fields,omitempty"`
}

type SaveCategoryRequest struct {
	Category             string
	ExpectedHeadRevision int64
	Change               CategoryChange
	IdempotencyKey       string
	RequestID            string
}

type CategoryDocument struct {
	Schema         string `json:"schema"`
	Category       string `json:"category"`
	HeadRevision   int64  `json:"head_revision"`
	ActiveRevision int64  `json:"active_revision"`
	Revision       int64  `json:"revision"`
	Status         string `json:"status"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
	// PendingCategories lists the categories whose head value differs from
	// the active revision. All categories share one revision stream, so
	// activating the head makes every listed category effective together.
	PendingCategories []string `json:"pending_categories"`
	Value             any      `json:"value"`
	Replayed          bool     `json:"-"`
}

type PreflightRevisionRequest struct {
	Revision       int64
	SnapshotSHA256 string
	// ExpectedPendingCategories, when supplied, must equal the categories the
	// revision would make effective; nil skips the check.
	ExpectedPendingCategories *[]string
	IdempotencyKey            string
	RequestID                 string
}

type ActivationStatus struct {
	TenantScopeID        string    `json:"tenant_scope_id"`
	TenantSourceRevision int64     `json:"tenant_source_revision"`
	PublicationID        string    `json:"publication_id"`
	ConfigVersionID      string    `json:"config_version_id"`
	RolloutID            string    `json:"rollout_id"`
	RolloutState         string    `json:"rollout_state"`
	ArtifactSHA256       string    `json:"artifact_sha256"`
	ReasonCode           string    `json:"reason_code"`
	CreatedAt            time.Time `json:"created_at"`
}

type ExpansionCheck struct {
	Actor                Actor
	Category             string
	ExpectedHeadRevision int64
	RequestID            string
}

type ExpansionAuthorizer interface {
	AuthorizeSystemConfigurationExpansion(context.Context, pgx.Tx, ExpansionCheck) error
}

type CategoryManager struct {
	core      *Service
	expansion ExpansionAuthorizer
}

func Categories() []string {
	return slices.Clone(categoryCatalog)
}

func EffectiveNodeMonitoring(value *NodeMonitoringConfiguration) NodeMonitoringConfiguration {
	return effectiveNodeMonitoring(value)
}

func NewCategoryManager(core *Service, expansion ExpansionAuthorizer) (*CategoryManager, error) {
	if core == nil || core.pool == nil || core.auditor == nil || core.now == nil {
		return nil, ErrInvalidStore
	}
	return &CategoryManager{core: core, expansion: expansion}, nil
}

func (manager *CategoryManager) GetActiveCategory(
	ctx context.Context,
	actor Actor,
	category string,
) (CategoryDocument, error) {
	if manager == nil || manager.core == nil {
		return CategoryDocument{}, ErrInvalidStore
	}
	if err := authorizeActorShape(actor); err != nil {
		return CategoryDocument{}, err
	}
	if !validCategory(category) {
		return CategoryDocument{}, ErrNotFound
	}
	var document CategoryDocument
	err := pgx.BeginFunc(ctx, manager.core.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		var head int64
		var active *int64
		err := tx.QueryRow(ctx, `SELECT head_revision,active_revision
			FROM system_configuration_streams WHERE platform_scope_id=$1`, actor.ScopeID).Scan(&head, &active)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if head == 0 {
			revision, err := projectBootstrapRevision()
			if err != nil {
				return err
			}
			document = categoryDocument(revision, category, head, 0, []string{})
			return nil
		}
		activeRevision := int64(0)
		if active != nil {
			activeRevision = *active
		}
		revision, err := loadRevision(ctx, tx, actor.ScopeID, head)
		if err != nil {
			return err
		}
		pending, err := pendingCategories(ctx, tx, actor.ScopeID, activeRevision, revision.Configuration)
		if err != nil {
			return err
		}
		document = categoryDocument(revision, category, head, activeRevision, pending)
		return nil
	})
	if err != nil {
		return CategoryDocument{}, fmt.Errorf("get active system configuration category: %w", err)
	}
	return document, nil
}

func (manager *CategoryManager) SaveCategory(
	ctx context.Context,
	actor Actor,
	request SaveCategoryRequest,
) (CategoryDocument, error) {
	if manager == nil || manager.core == nil {
		return CategoryDocument{}, ErrInvalidStore
	}
	if err := authorizeActorShape(actor); err != nil {
		return CategoryDocument{}, err
	}
	if request.ExpectedHeadRevision < 0 || request.ExpectedHeadRevision >= maxRevision ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) ||
		!validCategoryChange(request.Category, request.Change) {
		return CategoryDocument{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		Category             string         `json:"category"`
		ExpectedHeadRevision int64          `json:"expected_head_revision"`
		Change               CategoryChange `json:"change"`
	}{request.Category, request.ExpectedHeadRevision, request.Change})
	if err != nil {
		return CategoryDocument{}, err
	}

	var result CategoryDocument
	err = pgx.BeginFunc(ctx, manager.core.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		now, err := manager.core.currentTime()
		if err != nil {
			return err
		}
		write, replayed, err := manager.core.claimWrite(ctx, tx, actor, operationCreateDraft,
			request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if replayed {
			if err := json.Unmarshal(write.Response, &result); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}

		stream, err := lockStream(ctx, tx, actor.ScopeID, now)
		if err != nil {
			return err
		}
		if stream.Head != request.ExpectedHeadRevision || stream.Head >= maxRevision {
			return ErrRevisionConflict
		}
		var base Revision
		if stream.Head == 0 {
			base, err = projectBootstrapRevision()
		} else {
			base, _, _, err = loadRevisionRaw(ctx, tx, actor.ScopeID, stream.Head, true)
		}
		if err != nil {
			return err
		}
		next := applyCategoryChange(base.Configuration, request.Category, request.Change)
		normalized, snapshot, snapshotHash, err := CanonicalSnapshot(next)
		if err != nil {
			return err
		}
		if categoryChangeExpands(base.Configuration, normalized, request.Category) {
			if manager.expansion == nil {
				return ErrEntitlementDenied
			}
			err := manager.expansion.AuthorizeSystemConfigurationExpansion(ctx, tx, ExpansionCheck{
				Actor: actor, Category: request.Category, ExpectedHeadRevision: request.ExpectedHeadRevision,
				RequestID: request.RequestID,
			})
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return ErrEntitlementDenied
			}
		}

		revisionNumber := stream.Head + 1
		hashBytes, _ := hex.DecodeString(snapshotHash)
		_, err = tx.Exec(ctx, `INSERT INTO system_configuration_revisions (
			platform_scope_id,revision,status,canonical_schema,canonical_snapshot,snapshot_sha256,
			created_by_user_id,created_by_scope_id,created_at,state_changed_at
		) VALUES($1,$2,'draft',$3,$4,$5,$6,$1,$7,$7)`, actor.ScopeID, revisionNumber,
			canonicalSchema, snapshot, hashBytes, actor.UserID, now)
		if err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE system_configuration_streams
			SET head_revision=$2,updated_at=$3 WHERE platform_scope_id=$1 AND head_revision=$4`,
			actor.ScopeID, revisionNumber, now, request.ExpectedHeadRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		revision, err := loadRevision(ctx, tx, actor.ScopeID, revisionNumber)
		if err != nil {
			return err
		}
		if err := manager.core.appendAudit(ctx, tx, actor, revision, request.RequestID,
			operationCreateDraft, map[string]any{
				"category": request.Category, "expected_head_revision": request.ExpectedHeadRevision,
				"active_revision": stream.Active,
			}); err != nil {
			return err
		}
		pending, err := pendingCategories(ctx, tx, actor.ScopeID, stream.Active, revision.Configuration)
		if err != nil {
			return err
		}
		result = categoryDocument(revision, request.Category, revisionNumber, stream.Active, pending)
		return completeCategoryWrite(ctx, tx, actor, request.IdempotencyKey, result, now)
	})
	if errors.Is(err, ErrEntitlementDenied) {
		// The rejected transaction (including its provisional write claim) must
		// roll back before recording the denial in the append-only audit chain.
		auditErr := pgx.BeginFunc(ctx, manager.core.pool, func(tx pgx.Tx) error {
			if err := authorizePlatformActor(ctx, tx, actor, permissionManage); err != nil {
				return err
			}
			return manager.core.auditor.Append(ctx, tx, audit.Event{
				ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
				Action: operationCreateDraft, ResourceType: "system_configuration_category",
				ResourceID: request.Category, RequestID: request.RequestID, Result: "denied",
				Payload: map[string]any{
					"category": request.Category, "expected_head_revision": request.ExpectedHeadRevision,
					"reason": "entitlement_denied", "request_digest": hex.EncodeToString(digest[:]),
				},
			})
		})
		if auditErr != nil {
			return CategoryDocument{}, fmt.Errorf("audit denied system configuration category: %w", auditErr)
		}
	}
	if err != nil {
		return CategoryDocument{}, fmt.Errorf("save system configuration category: %w", err)
	}
	return result, nil
}

func (manager *CategoryManager) PreflightRevision(ctx context.Context, actor Actor,
	request PreflightRevisionRequest,
) (Revision, error) {
	if manager == nil || manager.core == nil {
		return Revision{}, ErrInvalidStore
	}
	if err := authorizeActorShape(actor); err != nil {
		return Revision{}, err
	}
	if request.Revision < 1 || request.Revision > maxRevision ||
		!hexSHA256Pattern.MatchString(request.SnapshotSHA256) ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) ||
		!validPendingCategories(request.ExpectedPendingCategories) {
		return Revision{}, ErrInvalidInput
	}
	var configuration Configuration
	var snapshotHash string
	referencesAvailable := false
	err := pgx.BeginFunc(ctx, manager.core.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		revision, err := loadRevision(ctx, tx, actor.ScopeID, request.Revision)
		if err != nil {
			return err
		}
		// Preflight only rejects a stale confirmation; activation is the gate
		// that requires one.
		if request.ExpectedPendingCategories != nil {
			var active *int64
			if err := tx.QueryRow(ctx, `SELECT active_revision FROM system_configuration_streams
				WHERE platform_scope_id=$1`, actor.ScopeID).Scan(&active); err != nil {
				return err
			}
			activeRevision := int64(0)
			if active != nil {
				activeRevision = *active
			}
			pending, err := pendingCategories(ctx, tx, actor.ScopeID, activeRevision, revision.Configuration)
			if err != nil {
				return err
			}
			if !pendingCategoriesMatch(request.ExpectedPendingCategories, pending) {
				return ErrPendingCategoriesChanged
			}
		}
		configuration = revision.Configuration
		snapshotHash = revision.SnapshotSHA256
		referencesAvailable, err = configurationReferencesAvailable(ctx, tx, actor.ScopeID, configuration)
		return err
	})
	if err != nil {
		return Revision{}, fmt.Errorf("prepare system configuration preflight: %w", err)
	}
	checks := configurationPreflightChecks(configuration, snapshotHash, referencesAvailable)
	return manager.core.RecordPreflight(ctx, actor, RecordPreflightRequest{
		Revision: request.Revision, ExpectedStatus: StatusDraft, SnapshotSHA256: request.SnapshotSHA256,
		Checks: checks, IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
	})
}

func configurationPreflightChecks(
	configuration Configuration,
	snapshotHash string,
	referencesAvailable bool,
) []PreflightCheck {
	check := func(name string, passed bool, code string) PreflightCheck {
		if passed {
			return PreflightCheck{Name: name, Status: CheckPass}
		}
		return PreflightCheck{Name: name, Status: CheckFail, Code: code}
	}

	_, _, canonicalHash, schemaErr := CanonicalSnapshot(configuration)
	resources := cloneResources(configuration.Resources)
	nginx := cloneNginx(configuration.Nginx)
	capacityOK := validateResources(&resources) == nil &&
		(nginx.ProxyCacheMaxBytes == 0 || nginx.ProxyCacheZoneBytes <= nginx.ProxyCacheMaxBytes)
	return []PreflightCheck{
		check(PreflightSchema, schemaErr == nil && canonicalHash == snapshotHash, "schema.invalid"),
		check(PreflightReferences, referencesAvailable, "references.missing"),
		check(PreflightCapacity, capacityOK, "capacity.invalid"),
		check(PreflightNginxSafety, validateNginx(&nginx) == nil, "nginx.invalid"),
		check(PreflightErrorPages,
			validateErrorPages(configuration.ErrorPages, resources.MaxCustomErrorPageBytes) == nil,
			"error_pages.invalid"),
	}
}

func configurationReferencesAvailable(
	ctx context.Context,
	tx pgx.Tx,
	platformScopeID uuid.UUID,
	configuration Configuration,
) (bool, error) {
	type target struct{ scope, id string }
	targets := make(map[target]struct{})
	for _, override := range configuration.Nginx.Overrides {
		targets[target{override.Scope, override.ScopeID}] = struct{}{}
	}
	for _, override := range configuration.Resources.Overrides {
		targets[target{override.Scope, override.ScopeID}] = struct{}{}
	}
	for _, override := range configuration.Defaults.Overrides {
		targets[target{override.Scope, override.ScopeID}] = struct{}{}
	}
	for target := range targets {
		var exists bool
		var err error
		switch target.scope {
		case ConfigurationScopeNode:
			err = tx.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM nodes WHERE scope_id=$1 AND id::text=$2 AND admin_state<>'retired'
			)`, platformScopeID, target.id).Scan(&exists)
		case ConfigurationScopeRegion:
			err = tx.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM region_catalog WHERE platform_scope_id=$1 AND display_id::text=$2
			)`, platformScopeID, target.id).Scan(&exists)
		default:
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
	}
	return true, nil
}

func (manager *CategoryManager) ActivateRevision(ctx context.Context, actor Actor,
	request ActivateRequest,
) (Revision, error) {
	if manager == nil || manager.core == nil {
		return Revision{}, ErrInvalidStore
	}
	// Category pages activate the whole shared head, so the caller must
	// confirm the full set of categories the activation makes effective.
	request.enforcePendingCategories = true
	return manager.core.Activate(ctx, actor, request)
}

func (manager *CategoryManager) RollbackRevision(ctx context.Context, actor Actor,
	request RollbackRequest,
) (Revision, error) {
	if manager == nil || manager.core == nil {
		return Revision{}, ErrInvalidStore
	}
	return manager.core.Rollback(ctx, actor, request)
}

func (manager *CategoryManager) ActivationStatus(ctx context.Context, actor Actor, revision int64) ([]ActivationStatus, error) {
	if manager == nil || manager.core == nil || revision < 1 || revision > maxRevision {
		return nil, ErrInvalidInput
	}
	if err := authorizeActorShape(actor); err != nil {
		return nil, err
	}
	result := make([]ActivationStatus, 0)
	err := pgx.BeginFunc(ctx, manager.core.pool, func(tx pgx.Tx) error {
		if err := authorizePlatformActor(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT binding.tenant_scope_id,binding.tenant_source_revision,
			binding.publication_id,binding.config_version_id,binding.rollout_id,rollout.status,
			encode(binding.artifact_sha256,'hex'),binding.reason_code,binding.created_at
			FROM system_configuration_edge_publications binding
			JOIN rollouts rollout ON rollout.configuration_scope_id=binding.tenant_scope_id AND rollout.id=binding.rollout_id
			WHERE binding.platform_scope_id=$1 AND binding.system_revision=$2
			ORDER BY binding.tenant_scope_id`, actor.ScopeID, revision)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item ActivationStatus
			if err := rows.Scan(&item.TenantScopeID, &item.TenantSourceRevision, &item.PublicationID,
				&item.ConfigVersionID, &item.RolloutID, &item.RolloutState, &item.ArtifactSHA256,
				&item.ReasonCode, &item.CreatedAt); err != nil {
				return err
			}
			result = append(result, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("get system configuration activation status: %w", err)
	}
	return result, nil
}

func completeCategoryWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	key string,
	result CategoryDocument,
	completedAt time.Time,
) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE system_configuration_write_requests
		SET response_body=$4,completed_at=$5
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 AND completed_at IS NULL`,
		actor.UserID, operationCreateDraft, key, encoded, completedAt)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func validCategory(category string) bool {
	return slices.Contains(categoryCatalog, category)
}

func validCategoryChange(category string, change CategoryChange) bool {
	if !validCategory(category) {
		return false
	}
	count := 0
	for _, present := range []bool{
		change.Nginx != nil,
		change.Defaults != nil,
		change.Resources != nil,
		change.ErrorPages != nil,
		change.Secret != nil,
		change.NodeMonitoring != nil,
		change.DDoSProtection != nil,
		change.AccessLogFields != nil,
	} {
		if present {
			count++
		}
	}
	if count != 1 {
		return false
	}
	switch category {
	case CategoryNginx:
		return change.Nginx != nil
	case CategoryDefaults:
		return change.Defaults != nil
	case CategoryResources:
		return change.Resources != nil
	case CategoryErrorPages:
		return change.ErrorPages != nil
	case CategorySecrets:
		if change.Secret == nil {
			return false
		}
		switch change.Secret.Intent {
		case SecretIntentClear:
			return change.Secret.Replacement == nil
		case SecretIntentReplace:
			return change.Secret.Replacement != nil && !change.Secret.Replacement.Masked
		default:
			return false
		}
	case CategoryNodeMonitoring:
		return change.NodeMonitoring != nil
	case CategoryDDoSProtection:
		return change.DDoSProtection != nil
	case CategoryAccessLogFields:
		return change.AccessLogFields != nil
	default:
		return false
	}
}

func applyCategoryChange(base Configuration, category string, change CategoryChange) Configuration {
	result := cloneConfiguration(base)
	switch category {
	case CategoryNginx:
		result.Nginx = cloneNginx(*change.Nginx)
	case CategoryDefaults:
		result.Defaults = cloneDefaults(*change.Defaults)
	case CategoryResources:
		result.Resources = cloneResources(*change.Resources)
	case CategoryErrorPages:
		result.ErrorPages = slices.Clone(*change.ErrorPages)
	case CategorySecrets:
		if change.Secret.Intent == SecretIntentClear {
			result.Secrets.ErrorPageStorage = nil
		} else {
			replacement := *change.Secret.Replacement
			result.Secrets.ErrorPageStorage = &replacement
		}
	case CategoryNodeMonitoring:
		nodeMonitoring := cloneNodeMonitoring(*change.NodeMonitoring)
		result.NodeMonitoring = &nodeMonitoring
	case CategoryDDoSProtection:
		result.DDoSProtection = cloneDDoSProtection(change.DDoSProtection)
	case CategoryAccessLogFields:
		result.AccessLogFields = cloneAccessLogFields(change.AccessLogFields)
	}
	return result
}

func categoryDocument(revision Revision, category string, head, active int64, pending []string) CategoryDocument {
	redacted := redactConfiguration(revision.Configuration)
	return CategoryDocument{
		Schema: canonicalSchema, Category: category, HeadRevision: head, ActiveRevision: active,
		Revision: revision.Revision, Status: revision.Status, SnapshotSHA256: revision.SnapshotSHA256,
		PendingCategories: pending, Value: categoryValue(redacted, category),
	}
}

// pendingCategories lists, in catalog order, the categories whose value in
// target differs from the active revision (the project defaults before the
// first activation).
func pendingCategories(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, active int64,
	target Configuration,
) ([]string, error) {
	var baseline Revision
	var err error
	if active > 0 {
		baseline, err = loadRevision(ctx, tx, scopeID, active)
	} else {
		baseline, err = projectBootstrapRevision()
	}
	if err != nil {
		return nil, err
	}
	return diffCategories(baseline.Configuration, target), nil
}

func diffCategories(before, after Configuration) []string {
	result := make([]string, 0)
	for _, category := range categoryCatalog {
		if !reflect.DeepEqual(categoryValue(before, category), categoryValue(after, category)) {
			result = append(result, category)
		}
	}
	return result
}

func validPendingCategories(expected *[]string) bool {
	if expected == nil {
		return true
	}
	seen := make(map[string]struct{}, len(*expected))
	for _, category := range *expected {
		if _, duplicate := seen[category]; duplicate || !validCategory(category) {
			return false
		}
		seen[category] = struct{}{}
	}
	return true
}

// pendingCategoriesMatch accepts an omitted expectation only when the
// activation affects at most one category, so legacy single-category callers
// keep working while a multi-category activation always needs confirmation.
func pendingCategoriesMatch(expected *[]string, actual []string) bool {
	if expected == nil {
		return len(actual) <= 1
	}
	want := slices.Clone(*expected)
	got := slices.Clone(actual)
	slices.Sort(want)
	slices.Sort(got)
	return slices.Equal(want, got)
}

func projectBootstrapRevision() (Revision, error) {
	configuration, _, snapshotHash, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
	if err != nil {
		return Revision{}, err
	}
	return Revision{
		Revision: 0, Status: StatusDraft, Configuration: configuration, SnapshotSHA256: snapshotHash,
	}, nil
}

func categoryValue(configuration Configuration, category string) any {
	switch category {
	case CategoryNginx:
		return configuration.Nginx
	case CategoryDefaults:
		return configuration.Defaults
	case CategoryResources:
		return configuration.Resources
	case CategoryErrorPages:
		return configuration.ErrorPages
	case CategorySecrets:
		return configuration.Secrets
	case CategoryNodeMonitoring:
		return effectiveNodeMonitoring(configuration.NodeMonitoring)
	case CategoryDDoSProtection:
		return EffectiveDDoSProtection(configuration.DDoSProtection)
	case CategoryAccessLogFields:
		return edgeconfig.EffectiveAccessLogFields(configuration.AccessLogFields)
	default:
		return nil
	}
}

func categoryChangeExpands(before, after Configuration, category string) bool {
	switch category {
	case CategoryNginx:
		return nginxExpands(before.Nginx, after.Nginx)
	case CategoryDefaults:
		return defaultsExpand(before.Defaults, after.Defaults)
	case CategoryResources:
		return resourcesExpand(before.Resources, after.Resources)
	case CategoryErrorPages:
		return errorPagesExpand(before.ErrorPages, after.ErrorPages)
	case CategorySecrets:
		return secretExpands(before.Secrets.ErrorPageStorage, after.Secrets.ErrorPageStorage)
	case CategoryNodeMonitoring:
		return nodeMonitoringExpands(
			effectiveNodeMonitoring(before.NodeMonitoring),
			effectiveNodeMonitoring(after.NodeMonitoring),
		)
	case CategoryDDoSProtection:
		// Kernel limits are a platform operation on its own nodes; they
		// consume no tenant quota or licensed module.
		return false
	case CategoryAccessLogFields:
		// Which fields the platform's own analytics store; no tenant quota.
		return false
	default:
		return true
	}
}

func nodeMonitoringExpands(before, after NodeMonitoringConfiguration) bool {
	// An omitted switch retains the Agent's legacy enabled behavior.
	monitoringEnabled := after.MonitorEnabled == nil || *after.MonitorEnabled
	if monitoringEnabled && before.MonitorEnabled != nil && !*before.MonitorEnabled {
		return true
	}
	if monitoringEnabled && (before.Protocol != after.Protocol || !reflect.DeepEqual(before.MonitorPort, after.MonitorPort) ||
		!reflect.DeepEqual(before.FailureRatio, after.FailureRatio) ||
		!reflect.DeepEqual(before.BandwidthOverLimit, after.BandwidthOverLimit) ||
		before.MonitorAction != "pause" && after.MonitorAction == "pause") {
		return true
	}
	if monitoringEnabled && !reflect.DeepEqual(before.MonitorGroups, after.MonitorGroups) &&
		(before.MonitorGroups == nil || after.MonitorGroups == nil ||
			stringSliceAdds(*before.MonitorGroups, *after.MonitorGroups)) {
		return true
	}
	if before.PortMode == PortModeDefault && after.PortMode == PortModeCustom {
		return true
	}
	if before.PortMode == PortModeCustom && before.CustomPort != nil && after.CustomPort != nil &&
		*before.CustomPort != *after.CustomPort {
		return true
	}
	return after.ProbeIntervalMS < before.ProbeIntervalMS ||
		after.ProbeTimeoutMS > before.ProbeTimeoutMS ||
		after.FailureThreshold > before.FailureThreshold ||
		after.RecoveryThreshold > before.RecoveryThreshold ||
		after.FailureDebounceMS > before.FailureDebounceMS ||
		after.RecoveryDebounceMS > before.RecoveryDebounceMS ||
		!before.RecoveryNotificationEnabled && after.RecoveryNotificationEnabled
}

func nginxExpands(before, after NginxLimits) bool {
	if anyIntegerIncrease([]int{
		before.WorkerProcesses, before.WorkerRlimitNoFile, before.WorkerShutdownTimeoutMS,
		before.WorkerConnections, before.ResolverTimeoutMS, before.GzipLevel,
		before.ProxyConnectTimeoutMS, before.ProxySendTimeoutMS, before.ProxyReadTimeoutMS,
		before.StreamProxyConnectTimeoutMS, before.StreamProxyTimeoutMS,
		before.KeepaliveRequests, before.KeepaliveTimeoutMS,
		before.ServerNamesHashMaxSize, before.ServerNamesHashBucketSize,
		before.LargeClientHeaderBuffers.Count,
	}, []int{
		after.WorkerProcesses, after.WorkerRlimitNoFile, after.WorkerShutdownTimeoutMS,
		after.WorkerConnections, after.ResolverTimeoutMS, after.GzipLevel,
		after.ProxyConnectTimeoutMS, after.ProxySendTimeoutMS, after.ProxyReadTimeoutMS,
		after.StreamProxyConnectTimeoutMS, after.StreamProxyTimeoutMS,
		after.KeepaliveRequests, after.KeepaliveTimeoutMS,
		after.ServerNamesHashMaxSize, after.ServerNamesHashBucketSize,
		after.LargeClientHeaderBuffers.Count,
	}) || before.GzipMinimumBytes > after.GzipMinimumBytes || anyInt64Increase([]int64{
		before.ProxyCacheMaxBytes, before.ProxyCacheZoneBytes, -before.ProxyCacheMinFreeBytes,
		before.ProxyMaxTempFileBytes, before.ClientBodyBufferSizeBytes,
		before.ClientMaxBodyBytes, before.LargeClientHeaderBuffers.SizeBytes,
	}, []int64{
		after.ProxyCacheMaxBytes, after.ProxyCacheZoneBytes, -after.ProxyCacheMinFreeBytes,
		after.ProxyMaxTempFileBytes, after.ClientBodyBufferSizeBytes,
		after.ClientMaxBodyBytes, after.LargeClientHeaderBuffers.SizeBytes,
	}) {
		return true
	}
	if enabled(before.GzipVary, after.GzipVary) || enabled(before.ServerAddrOutgoing, after.ServerAddrOutgoing) ||
		enabled(before.ProxyRequestBuffering, after.ProxyRequestBuffering) ||
		enabled(before.ProxyBuffering, after.ProxyBuffering) ||
		enabled(before.LogNotFound, after.LogNotFound) || enabled(before.ServerTokens, after.ServerTokens) {
		return true
	}
	if before.LogsDir != after.LogsDir || before.GzipHTTPVersion != after.GzipHTTPVersion ||
		before.ProxyHTTPVersion != after.ProxyHTTPVersion ||
		before.ServerHeader != after.ServerHeader || before.DefaultMIMEType != after.DefaultMIMEType ||
		!reflect.DeepEqual(before.Overrides, after.Overrides) {
		return true
	}
	return stringSliceAdds(before.ResolverAddresses, after.ResolverAddresses) ||
		stringSliceAdds(before.ProxyCacheMethods, after.ProxyCacheMethods) ||
		stringSliceAdds(before.ProxyNextUpstream, after.ProxyNextUpstream)
}

func defaultsExpand(before, after DefaultReferences) bool {
	for _, pair := range [][2]*RevisionReference{
		{before.SiteTemplate, after.SiteTemplate}, {before.CachePolicy, after.CachePolicy},
		{before.WAFPolicy, after.WAFPolicy}, {before.CCPolicy, after.CCPolicy},
		{before.ACLPolicy, after.ACLPolicy},
	} {
		if referenceExpands(pair[0], pair[1]) {
			return true
		}
	}
	if !reflect.DeepEqual(before.Website, after.Website) ||
		!reflect.DeepEqual(before.Stream, after.Stream) ||
		!reflect.DeepEqual(before.Certificate, after.Certificate) ||
		!reflect.DeepEqual(before.Overrides, after.Overrides) {
		return true
	}
	return after.ListenPort > before.ListenPort || after.OriginPort > before.OriginPort ||
		after.HTTPSPort > before.HTTPSPort || before.OriginScheme != after.OriginScheme
}

func resourcesExpand(before, after ResourceLimits) bool {
	if !reflect.DeepEqual(before.StreamCustomPortNotAllow, after.StreamCustomPortNotAllow) ||
		!reflect.DeepEqual(before.CustomPortNotAllow, after.CustomPortNotAllow) ||
		!reflect.DeepEqual(before.CustomPortAllow, after.CustomPortAllow) ||
		!reflect.DeepEqual(before.Overrides, after.Overrides) ||
		enabled(before.ListenDefaultHTTP80, after.ListenDefaultHTTP80) {
		return true
	}
	return anyIntegerIncrease([]int{
		before.MaxSitesPerTenant, before.MaxOriginsPerSite, before.MaxDomainsPerSite,
		before.MaxCertificatesPerTenant, before.MaxBlacklistIPsPerSite, before.MaxWhitelistIPsPerSite,
		before.DailyURLPurgeLimit, before.DailyDirectoryPurgeLimit, before.DailyPrewarmLimit,
		before.DailyIPUnlockLimit, before.IPUnlockPerRequestLimit,
		before.MaxACLRulesPerPolicy, before.MaxCCRulesPerPolicy, before.MinimumRelatedConfigLimit,
		before.RelatedConfigMaxMultiplier, before.StreamMinimumRelatedConfigLimit,
		before.StreamRelatedConfigMaxMultiplier, before.DailyAccessLogDownloadLimit,
		before.AccessLogRetentionHours,
	}, []int{
		after.MaxSitesPerTenant, after.MaxOriginsPerSite, after.MaxDomainsPerSite,
		after.MaxCertificatesPerTenant, after.MaxBlacklistIPsPerSite, after.MaxWhitelistIPsPerSite,
		after.DailyURLPurgeLimit, after.DailyDirectoryPurgeLimit, after.DailyPrewarmLimit,
		after.DailyIPUnlockLimit, after.IPUnlockPerRequestLimit,
		after.MaxACLRulesPerPolicy, after.MaxCCRulesPerPolicy, after.MinimumRelatedConfigLimit,
		after.RelatedConfigMaxMultiplier, after.StreamMinimumRelatedConfigLimit,
		after.StreamRelatedConfigMaxMultiplier, after.DailyAccessLogDownloadLimit,
		after.AccessLogRetentionHours,
	}) || after.MaxCustomErrorPageBytes > before.MaxCustomErrorPageBytes ||
		before.AccessLogTemporaryDir != after.AccessLogTemporaryDir
}

func errorPagesExpand(before, after []ErrorPageMetadata) bool {
	if len(after) > len(before) {
		return true
	}
	available := make(map[ErrorPageMetadata]int, len(before))
	for _, item := range before {
		available[item]++
	}
	for _, item := range after {
		if available[item] == 0 {
			return true
		}
		available[item]--
	}
	return false
}

func secretExpands(before, after *SecretEnvelopeReference) bool {
	switch {
	case before == nil && after == nil:
		return false
	case before == nil && after != nil:
		return true
	case before != nil && after == nil:
		return false
	default:
		return *before != *after
	}
}

func referenceExpands(before, after *RevisionReference) bool {
	switch {
	case before == nil && after == nil:
		return false
	case before == nil && after != nil:
		return true
	case before != nil && after == nil:
		return false
	default:
		return *before != *after
	}
}

func anyIntegerIncrease(before, after []int) bool {
	for index := range before {
		if after[index] > before[index] {
			return true
		}
	}
	return false
}

func anyInt64Increase(before, after []int64) bool {
	for index := range before {
		if after[index] > before[index] {
			return true
		}
	}
	return false
}

func enabled(before, after bool) bool {
	return !before && after
}

func stringSliceAdds(before, after []string) bool {
	available := make(map[string]int, len(before))
	for _, item := range before {
		available[item]++
	}
	for _, item := range after {
		if available[item] == 0 {
			return true
		}
		available[item]--
	}
	return false
}
