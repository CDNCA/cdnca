package dnsproviderremotesource

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// HubRecord is one provider record as the page shows it.
type HubRecord struct {
	RecordRef string      `json:"record_ref"`
	Name      string      `json:"name"` // relative owner, "@" for the domain itself
	FQDN      string      `json:"fqdn"`
	Type      string      `json:"type"`
	Value     string      `json:"value"` // CNAME without the trailing dot, TXT unquoted
	TTL       uint32      `json:"ttl"`
	Line      string      `json:"line"`
	Weight    uint32      `json:"weight"`
	Managed   *HubManaged `json:"managed"`
}

// HubManaged marks a record this platform uses (ADR 0020 §3.3): changing or
// deleting it needs confirm_managed.
type HubManaged struct {
	Kind       string `json:"kind"` // site_cname | site_auto_dns | cdn_validation | acme_challenge
	SiteID     string `json:"site_id"`
	SiteDomain string `json:"site_domain"`
}

type HubRecordList struct {
	ProviderID uuid.UUID   `json:"provider_id"`
	Apex       string      `json:"apex"`
	Items      []HubRecord `json:"items"`
	// Skipped counts listed A/AAAA/CNAME/TXT records the page cannot show
	// (wildcard owners and other names outside the hostname form).
	Skipped int `json:"skipped"`
}

type HubRecordQuery struct {
	Type  string
	Query string
}

// ListRecords reads the domain's records live from the provider.
func (h *Hub) ListRecords(ctx context.Context, actor HubActor, providerID uuid.UUID, apex string, query HubRecordQuery) (HubRecordList, error) {
	apex, ok := hubApex(apex)
	if !ok {
		return HubRecordList{}, ErrHubNotFound
	}
	filterType := strings.ToUpper(strings.TrimSpace(query.Type))
	if _, ok := hubRecordType(filterType); filterType != "" && !ok {
		return HubRecordList{}, &HubFieldError{Field: "type"}
	}
	needle := strings.ToLower(strings.TrimSpace(query.Query))
	callCtx, cancel := context.WithTimeout(ctx, hubCallTimeout)
	defer cancel()
	list := HubRecordList{ProviderID: providerID, Apex: apex, Items: []HubRecord{}}
	err := h.withAccount(callCtx, actor, "dns.read", providerID, apex, func(tx pgx.Tx, account hubAccount, config dnsproviderremote.ProviderConfig) error {
		records, skipped, err := h.remote.ListHubRecords(callCtx, config, "")
		if err != nil {
			return err
		}
		managed, err := h.managedRecords(callCtx, tx, actor.ScopeID, providerID, apex)
		if err != nil {
			return err
		}
		list.Skipped = skipped
		for _, record := range records {
			item := hubRecordView(apex, record, managed)
			if filterType != "" && item.Type != filterType ||
				needle != "" && !strings.Contains(item.Name, needle) && !strings.Contains(strings.ToLower(item.Value), needle) {
				continue
			}
			list.Items = append(list.Items, item)
		}
		sort.SliceStable(list.Items, func(left, right int) bool {
			a, b := list.Items[left], list.Items[right]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			if a.Type != b.Type {
				return a.Type < b.Type
			}
			return a.Line < b.Line
		})
		_, err = tx.Exec(callCtx, `UPDATE tenant_dns_domains SET record_count=$4, records_listed_at=$5
			WHERE scope_id=$1 AND provider_id=$2 AND apex=$3`, actor.ScopeID, providerID, apex, len(records), h.now().UTC())
		return err
	})
	return list, err
}

// withAccount runs fn in one transaction holding the own account FOR SHARE
// (a credential replacement waits for the provider call) once the actor is
// authorized and apex is in the account's cached domain list.
func (h *Hub) withAccount(ctx context.Context, actor HubActor, permission string, providerID uuid.UUID, apex string,
	fn func(pgx.Tx, hubAccount, dnsproviderremote.ProviderConfig) error) error {
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := h.authorize(ctx, tx, actor, permission); err != nil {
		return err
	}
	account, err := h.account(ctx, tx, actor.ScopeID, providerID, true)
	if err != nil {
		return err
	}
	defer clear(account.Ciphertext)
	var listed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_dns_domains WHERE scope_id=$1 AND provider_id=$2 AND apex=$3)`,
		actor.ScopeID, providerID, apex).Scan(&listed); err != nil {
		return err
	}
	if !listed {
		return ErrHubNotFound
	}
	if !account.usable() {
		return ErrHubUnsupported
	}
	credentials, err := h.credentials(actor.ScopeID, account)
	if err != nil {
		return err
	}
	defer clearCredentials(credentials)
	if err := fn(tx, account, hubProviderConfig(actor.ScopeID, account, apex, credentials, uuid.NewString())); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func hubApex(raw string) (string, bool) {
	apex := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	return apex, hubApexPattern.MatchString(apex) && len(apex) <= 253
}

func hubRecordView(apex string, record dnsproviderremote.ZoneRecord, managed map[string]HubManaged) HubRecord {
	fqdn := strings.TrimSuffix(record.Name, ".")
	name := "@"
	if fqdn != apex {
		name = strings.TrimSuffix(fqdn, "."+apex)
	}
	value := record.Value
	if record.Type == dnscheck.RecordCNAME {
		value = strings.TrimSuffix(value, ".")
	}
	view := HubRecord{RecordRef: encodeHubRecordRef(record.ID), Name: name, FQDN: fqdn, Type: record.Type.String(),
		Value: value, TTL: record.TTL, Line: hubLine(record.Line), Weight: record.Weight}
	if marker, ok := managed[managedKey(view.Type, fqdn, value)]; ok {
		view.Managed = &marker
	}
	return view
}

// hubLine shows the provider default line as 默认.
func hubLine(line string) string {
	if line == "" || line == "default" {
		return dnsproviderremote.LineDefault
	}
	return line
}

func encodeHubRecordRef(id string) string {
	return "r1." + base64.RawURLEncoding.EncodeToString([]byte(id))
}

func decodeHubRecordRef(ref string) (string, bool) {
	encoded, found := strings.CutPrefix(ref, "r1.")
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if !found || err != nil || len(raw) == 0 || len(raw) > 512 {
		return "", false
	}
	return string(raw), true
}

func managedKey(recordType, fqdn, value string) string {
	if recordType == "CNAME" {
		value = strings.ToLower(strings.TrimSuffix(value, "."))
	}
	return recordType + "\x00" + strings.ToLower(fqdn) + "\x00" + value
}

// managedRecords are the records of apex this platform uses, keyed by
// managedKey: a site domain's CNAME to the site CNAME (site_auto_dns when
// the site's 自动添加记录 task writes through this account), a third-party
// CDN validation TXT of a site of the scope, and an outstanding ACME DNS-01
// TXT of the scope.
func (h *Hub) managedRecords(ctx context.Context, tx pgx.Tx, scopeID, providerID uuid.UUID, apex string) (map[string]HubManaged, error) {
	managed := map[string]HubManaged{}
	suffix := "%." + apex
	rows, err := tx.Query(ctx, `SELECT site.id::text, current.canonical_domain, lower(rtrim(site.cname,'.')),
			EXISTS(SELECT 1 FROM site_auto_dns_tasks task WHERE task.site_id=site.id AND task.provider_id=$2)
		FROM sites site
		JOIN LATERAL (
			SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain, fact.action
			FROM site_domain_facts fact WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
			ORDER BY fact.canonical_domain, fact.global_sequence DESC
		) current ON current.action='activate'
		WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND site.cname<>''
		  AND (current.canonical_domain=$3 OR current.canonical_domain LIKE $4)`, scopeID, providerID, apex, suffix)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var siteID, domain, cname string
		var auto bool
		if err := rows.Scan(&siteID, &domain, &cname, &auto); err != nil {
			rows.Close()
			return nil, err
		}
		kind := "site_cname"
		if auto {
			kind = "site_auto_dns"
		}
		managed[managedKey("CNAME", domain, cname)] = HubManaged{Kind: kind, SiteID: siteID, SiteDomain: domain}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT site.id::text, site.domain, record.record_name, record.record_value
		FROM site_supply_cdn_validation_records record
		JOIN sites site ON site.id=record.site_id AND site.scope_id=$1
		WHERE record.wanted AND record.state='published' AND (record.record_name=$2 OR record.record_name LIKE $3)`,
		scopeID, apex, suffix)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var siteID, siteDomain, name, value string
		if err := rows.Scan(&siteID, &siteDomain, &name, &value); err != nil {
			rows.Close()
			return nil, err
		}
		managed[managedKey("TXT", name, value)] = HubManaged{Kind: "cdn_validation", SiteID: siteID, SiteDomain: siteDomain}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT attempt.record_name, attempt.exact_value, attempt.identifier
		FROM acme_issuance_challenge_attempts attempt
		JOIN LATERAL (SELECT state FROM acme_issuance_challenge_events event
			WHERE event.tenant_scope_id=attempt.tenant_scope_id AND event.operation_id=attempt.operation_id
			  AND event.attempt_id=attempt.attempt_id ORDER BY revision DESC LIMIT 1) latest ON latest.state<>'cleaned'
		WHERE attempt.tenant_scope_id=$1 AND (rtrim(attempt.record_name,'.') LIKE $2)`, scopeID, suffix)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name, value, identifier string
		if err := rows.Scan(&name, &value, &identifier); err != nil {
			rows.Close()
			return nil, err
		}
		managed[managedKey("TXT", strings.TrimSuffix(name, "."), value)] = HubManaged{Kind: "acme_challenge", SiteDomain: identifier}
	}
	rows.Close()
	return managed, rows.Err()
}

// HubRecordInput is a record as the member enters it.
type HubRecordInput struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	TTL    uint32 `json:"ttl"`
	Line   string `json:"line"`
	Weight uint32 `json:"weight"`
}

// HubMutation is one create / update / delete.
type HubMutation struct {
	ProviderID     uuid.UUID
	Apex           string
	Action         string // create | update | delete
	RecordRef      string
	Record         HubRecordInput  // create, update
	Expected       *HubRecordInput // update, delete: the value the member saw
	ConfirmManaged bool
	IdempotencyKey string
}

// HubMutationResult is stored with the operation and replayed for the same
// Idempotency-Key.
type HubMutationResult struct {
	OpID   uuid.UUID  `json:"op_id"`
	State  string     `json:"state"` // applied | uncertain
	Record *HubRecord `json:"record"`
	Status int        `json:"-"`
}

// HubChangedError: the provider's record no longer matches expected.
type HubChangedError struct{ Current *HubRecord }

func (e *HubChangedError) Error() string { return "dns hub: record changed" }

// HubManagedError: the record is used by this platform and confirm_managed
// was not given.
type HubManagedError struct{ Managed HubManaged }

func (e *HubManagedError) Error() string { return "dns hub: record is managed by the platform" }

// ErrHubConflict: a create collides with records already under the name.
var ErrHubConflict = errors.New("dns hub: record conflict")

// Mutate applies one change through the account and reads it back.
func (h *Hub) Mutate(ctx context.Context, actor HubActor, mutation HubMutation) (HubMutationResult, error) {
	apex, ok := hubApex(mutation.Apex)
	if !ok {
		return HubMutationResult{}, ErrHubNotFound
	}
	mutation.Apex = apex
	desired, expected, err := validateHubMutation(&mutation)
	if err != nil {
		return HubMutationResult{}, err
	}
	digest, err := hubMutationDigest(mutation)
	if err != nil {
		return HubMutationResult{}, ErrHubInvalid
	}
	callCtx, cancel := context.WithTimeout(ctx, hubCallTimeout)
	defer cancel()
	var result HubMutationResult
	err = h.withAccount(callCtx, actor, "dns.manage", mutation.ProviderID, apex, func(tx pgx.Tx, account hubAccount, config dnsproviderremote.ProviderConfig) error {
		// One member's key runs once at a time; a replay returns the stored result.
		if _, err := tx.Exec(callCtx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 599))`,
			actor.ScopeID.String()+"/"+actor.UserID.String()+"/"+mutation.IdempotencyKey); err != nil {
			return err
		}
		replay, retryOpID, err := h.replay(callCtx, tx, actor, mutation.IdempotencyKey, digest)
		if err != nil || replay != nil {
			if replay != nil {
				result = *replay
			}
			return err
		}
		if !dnsproviderremote.HubRecordTypeSupported(account.ProviderType, recordTypeOf(desired, expected)) ||
			desired != nil && !hubLineSupported(account.ProviderType, desired.line) ||
			desired != nil && desired.weight != 0 && !dnsproviderremote.HubSupportsWeight(account.ProviderType) {
			return ErrHubUnsupported
		}
		opID := retryOpID
		if opID == uuid.Nil {
			opID = uuid.New()
		}
		config.OperationID = opID.String()
		outcome, err := h.apply(callCtx, tx, actor, account, config, mutation, desired, expected)
		if err != nil {
			var provider *dnsproviderremote.Error
			if !errors.As(err, &provider) {
				return err // validation, changed, managed, conflict: nothing was written
			}
			if recordErr := h.recordOp(callCtx, tx, actor, account, mutation, digest, opID, outcome, err, retryOpID != uuid.Nil); recordErr != nil {
				return recordErr
			}
			if commitErr := tx.Commit(callCtx); commitErr != nil {
				return commitErr
			}
			return err
		}
		outcome.result.OpID = opID
		if err := h.recordOp(callCtx, tx, actor, account, mutation, digest, opID, outcome, nil, retryOpID != uuid.Nil); err != nil {
			return err
		}
		result = outcome.result
		return nil
	})
	if err != nil {
		return HubMutationResult{}, err
	}
	return result, nil
}

// hubOutcome carries what the change did (before/after summaries for the
// op row and the audit event).
type hubOutcome struct {
	result         HubMutationResult
	before, after  *HubRecordInput
	recordName     string
	recordType     string
	providerRecord string
}

func (h *Hub) apply(ctx context.Context, tx pgx.Tx, actor HubActor, account hubAccount, config dnsproviderremote.ProviderConfig,
	mutation HubMutation, desired, expected *hubWanted) (hubOutcome, error) {
	owner := desired
	if owner == nil {
		owner = expected
	}
	outcome := hubOutcome{recordName: strings.TrimSuffix(owner.fqdn, "."), recordType: owner.recordType.String()}
	if desired != nil {
		outcome.after = desired.summary(mutation.Apex)
	}
	if expected != nil {
		outcome.before = expected.summary(mutation.Apex)
	}
	current, _, err := h.remote.ListHubRecords(ctx, config, owner.fqdn)
	if err != nil {
		return outcome, err
	}
	managed, err := h.managedRecords(ctx, tx, actor.ScopeID, account.ID, mutation.Apex)
	if err != nil {
		return outcome, err
	}
	operation := dnscheck.ProviderOperation{Name: owner.fqdn, Type: owner.recordType, Reason: "dns_hub"}
	if desired != nil {
		operation.Value, operation.TTL, operation.Line, operation.Weight = desired.value, desired.ttl, desired.line, desired.weight
	}
	switch mutation.Action {
	case "create":
		operation.Action = dnscheck.ProviderCreate
		for _, record := range current {
			if desired.matches(record) {
				// Already there (a retried request): adopt it, write nothing.
				view := hubRecordView(mutation.Apex, record, managed)
				outcome.result = HubMutationResult{State: "applied", Record: &view, Status: 201}
				outcome.providerRecord = record.ID
				return outcome, nil
			}
			if sameHubLine(record.Line, desired.line) &&
				(desired.recordType == dnscheck.RecordCNAME || record.Type == dnscheck.RecordCNAME) {
				return outcome, ErrHubConflict
			}
		}
	case "update", "delete":
		recordID, _ := decodeHubRecordRef(mutation.RecordRef)
		var target *dnsproviderremote.ZoneRecord
		for index := range current {
			if current[index].ID == recordID {
				target = &current[index]
				break
			}
		}
		if target == nil {
			return outcome, &HubChangedError{}
		}
		view := hubRecordView(mutation.Apex, *target, managed)
		if !expected.matches(*target) {
			return outcome, &HubChangedError{Current: &view}
		}
		if view.Managed != nil && !mutation.ConfirmManaged {
			return outcome, &HubManagedError{Managed: *view.Managed}
		}
		operation.RecordID = target.ID
		operation.PreviousValue, operation.PreviousTTL = target.Value, target.TTL
		operation.PreviousLine, operation.PreviousWeight = target.Line, target.Weight
		if mutation.Action == "update" {
			operation.Action = dnscheck.ProviderUpdate
		} else {
			operation.Action = dnscheck.ProviderDelete
			operation.Value, operation.TTL, operation.Line, operation.Weight = target.Value, target.TTL, target.Line, target.Weight
		}
	}
	providerRecord, err := h.remote.Mutate(ctx, config, operation)
	switch code := dnsproviderremote.ErrorCodeOf(err); {
	case err == nil:
	case code == dnsproviderremote.CodeTimeout || code == dnsproviderremote.CodeCancelled:
		// The provider may have applied it: the member re-reads the records.
		outcome.result = HubMutationResult{State: "uncertain", Status: 202}
		return outcome, nil
	case code == dnsproviderremote.CodeUnsupported || code == dnsproviderremote.CodeLineNotInPlan:
		return outcome, ErrHubUnsupported // refused before any call (e.g. Huawei line change)
	case code == dnsproviderremote.CodeInvalidInput:
		return outcome, ErrHubInvalid
	default:
		return outcome, err
	}
	outcome.providerRecord = providerRecord
	after, _, err := h.remote.ListHubRecords(ctx, config, owner.fqdn)
	if err != nil {
		outcome.result = HubMutationResult{State: "uncertain", Status: 202}
		return outcome, nil
	}
	if mutation.Action == "delete" {
		for _, record := range after {
			if record.ID == operation.RecordID && expected.matches(record) {
				outcome.result = HubMutationResult{State: "uncertain", Status: 202}
				return outcome, nil
			}
		}
		outcome.result = HubMutationResult{State: "applied", Status: 200}
		return outcome, nil
	}
	for _, record := range after {
		if desired.matchesWritten(record) {
			view := hubRecordView(mutation.Apex, record, managed)
			status := 200
			if mutation.Action == "create" {
				status = 201
			}
			outcome.result = HubMutationResult{State: "applied", Record: &view, Status: status}
			if record.ID != "" {
				outcome.providerRecord = record.ID
			}
			return outcome, nil
		}
	}
	outcome.result = HubMutationResult{State: "uncertain", Status: 202}
	return outcome, nil
}

// replay returns the stored result of key (same request), the ID of a failed
// attempt to retry, or ErrHubIdempotency for another request.
func (h *Hub) replay(ctx context.Context, tx pgx.Tx, actor HubActor, key, digest string) (*HubMutationResult, uuid.UUID, error) {
	var (
		id                  uuid.UUID
		storedDigest, state string
		status              int
		response            []byte
	)
	err := tx.QueryRow(ctx, `SELECT id, request_sha256, state, response_status, response FROM tenant_dns_record_ops
		WHERE scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3`, actor.ScopeID, actor.UserID, key).
		Scan(&id, &storedDigest, &state, &status, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, nil
	}
	if err != nil {
		return nil, uuid.Nil, err
	}
	if storedDigest != digest {
		return nil, uuid.Nil, ErrHubIdempotency
	}
	if state == "failed" {
		return nil, id, nil
	}
	var result HubMutationResult
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, uuid.Nil, err
	}
	result.Status = status
	return &result, uuid.Nil, nil
}

func (h *Hub) recordOp(ctx context.Context, tx pgx.Tx, actor HubActor, account hubAccount, mutation HubMutation,
	digest string, opID uuid.UUID, outcome hubOutcome, failure error, retry bool) error {
	state, errorCode, status := outcome.result.State, "", outcome.result.Status
	response, err := json.Marshal(outcome.result)
	if err != nil {
		return err
	}
	if failure != nil {
		state, errorCode, status, response = "failed", providerErrorCode(failure), 502, []byte("{}")
	}
	before, after := summaryJSON(outcome.before), summaryJSON(outcome.after)
	now := h.now().UTC()
	if retry {
		_, err = tx.Exec(ctx, `UPDATE tenant_dns_record_ops SET before=$2, after=$3, state=$4, provider_record_id=$5,
			error_code=$6, response_status=$7, response=$8, request_id=$9, updated_at=$10 WHERE id=$1`,
			opID, before, after, state, outcome.providerRecord, errorCode, status, response, actor.RequestID, now)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO tenant_dns_record_ops(id,scope_id,provider_id,apex,actor_user_id,idempotency_key,
			request_sha256,action,record_type,record_name,before,after,state,provider_record_id,error_code,
			response_status,response,request_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$19)`,
			opID, actor.ScopeID, account.ID, mutation.Apex, actor.UserID, mutation.IdempotencyKey, digest, mutation.Action,
			outcome.recordType, outcome.recordName, before, after, state, outcome.providerRecord, errorCode, status, response,
			actor.RequestID, now)
	}
	if err != nil {
		return err
	}
	auditResult := "success"
	if failure != nil {
		auditResult = "failure"
	}
	return h.auditor.Append(ctx, tx, hubRecordAuditEvent(actor, account, mutation, opID, outcome, auditResult, errorCode))
}

func summaryJSON(summary *HubRecordInput) any {
	if summary == nil {
		return nil
	}
	return summary
}

// hubMutationDigest identifies the request for Idempotency-Key reuse.
func hubMutationDigest(mutation HubMutation) (string, error) {
	raw, err := json.Marshal(struct {
		Provider, Apex, Action, Ref string
		Record                      HubRecordInput
		Expected                    *HubRecordInput
		Confirm                     bool
	}{mutation.ProviderID.String(), mutation.Apex, mutation.Action, mutation.RecordRef, mutation.Record, mutation.Expected, mutation.ConfirmManaged})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

// hubWanted is a validated record (owner FQDN with trailing dot, value in
// the adapters' canonical form).
type hubWanted struct {
	fqdn       string
	recordType dnscheck.RecordType
	value      string
	ttl        uint32
	line       string
	weight     uint32
}

func recordTypeOf(desired, expected *hubWanted) dnscheck.RecordType {
	if desired != nil {
		return desired.recordType
	}
	return expected.recordType
}

func (wanted *hubWanted) summary(apex string) *HubRecordInput {
	value := wanted.value
	if wanted.recordType == dnscheck.RecordCNAME {
		value = strings.TrimSuffix(value, ".")
	}
	name := strings.TrimSuffix(wanted.fqdn, ".")
	if name == apex {
		name = "@"
	} else {
		name = strings.TrimSuffix(name, "."+apex)
	}
	return &HubRecordInput{Name: name, Type: wanted.recordType.String(), Value: value, TTL: wanted.ttl,
		Line: hubLine(wanted.line), Weight: wanted.weight}
}

// matches: the record is exactly this one (expected comparison).
func (wanted *hubWanted) matches(record dnsproviderremote.ZoneRecord) bool {
	return wanted.matchesWritten(record) && record.TTL == wanted.ttl
}

// matchesWritten ignores the TTL: a provider may raise it to its floor
// (name.com 300).
func (wanted *hubWanted) matchesWritten(record dnsproviderremote.ZoneRecord) bool {
	return record.Name == wanted.fqdn && record.Type == wanted.recordType && record.Value == wanted.value &&
		sameHubLine(record.Line, wanted.line) && record.Weight == wanted.weight
}

func sameHubLine(left, right string) bool { return hubLine(left) == hubLine(right) }

func hubLineSupported(providerType, line string) bool {
	for _, supported := range dnsproviderremote.SupportedLines(providerType) {
		if supported == hubLine(line) {
			return true
		}
	}
	return false
}

// validateHubMutation checks the request shape and returns the desired
// record (create, update) and the expected one (update, delete).
func validateHubMutation(mutation *HubMutation) (*hubWanted, *hubWanted, error) {
	if mutation.ProviderID == uuid.Nil {
		return nil, nil, ErrHubNotFound
	}
	var desired, expected *hubWanted
	var err error
	switch mutation.Action {
	case "create":
		if mutation.Expected != nil || mutation.RecordRef != "" {
			return nil, nil, &HubFieldError{Field: "expected"}
		}
		desired, err = validateHubRecord(mutation.Apex, mutation.Record, "")
	case "update", "delete":
		if _, ok := decodeHubRecordRef(mutation.RecordRef); !ok {
			return nil, nil, ErrHubNotFound
		}
		if mutation.Expected == nil {
			return nil, nil, &HubFieldError{Field: "expected"}
		}
		if expected, err = validateHubRecord(mutation.Apex, *mutation.Expected, "expected."); err != nil {
			return nil, nil, err
		}
		if mutation.Action == "update" {
			desired, err = validateHubRecord(mutation.Apex, mutation.Record, "")
			if err == nil && desired.fqdn != expected.fqdn {
				return nil, nil, &HubFieldError{Field: "name"} // rename = delete + create
			}
			if err == nil && desired.recordType != expected.recordType {
				return nil, nil, &HubFieldError{Field: "type"}
			}
		} else if mutation.Record != (HubRecordInput{}) {
			return nil, nil, &HubFieldError{Field: "record"}
		}
	default:
		return nil, nil, &HubFieldError{Field: "action"}
	}
	if err != nil {
		return nil, nil, err
	}
	return desired, expected, nil
}

func validateHubRecord(apex string, input HubRecordInput, prefix string) (*hubWanted, error) {
	recordType, ok := hubRecordType(input.Type)
	if !ok {
		return nil, &HubFieldError{Field: prefix + "type"}
	}
	name := strings.ToLower(strings.TrimSpace(input.Name))
	fqdn := apex + "."
	if name != "@" && name != "" {
		fqdn = name + "." + apex + "."
		if strings.HasSuffix(name, ".") || !hubApexPattern.MatchString(name+"."+apex) || len(fqdn) > 254 {
			return nil, &HubFieldError{Field: prefix + "name"}
		}
	}
	if input.TTL == 0 || input.TTL > 7*24*60*60 {
		return nil, &HubFieldError{Field: prefix + "ttl"}
	}
	if input.Weight > 100 || len(input.Line) > 64 || strings.ContainsAny(input.Line, "\r\n\x00") || input.Line != strings.TrimSpace(input.Line) {
		return nil, &HubFieldError{Field: prefix + "line"}
	}
	value := strings.TrimSpace(input.Value)
	switch recordType {
	case dnscheck.RecordA, dnscheck.RecordAAAA:
		address, err := netip.ParseAddr(value)
		if err != nil || recordType == dnscheck.RecordA && !address.Is4() ||
			recordType == dnscheck.RecordAAAA && (!address.Is6() || address.Is4In6()) {
			return nil, &HubFieldError{Field: prefix + "value"}
		}
		value = address.String()
	case dnscheck.RecordCNAME:
		target := strings.TrimSuffix(strings.ToLower(value), ".")
		if !hubApexPattern.MatchString(target) {
			return nil, &HubFieldError{Field: prefix + "value"}
		}
		value = target + "."
	case dnscheck.RecordTXT:
		value = input.Value // TXT text is kept exactly
		// expected may be any text the provider holds; new text must be writable.
		if prefix == "" && !dnsproviderremote.HubTXTWritable(value) ||
			value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n\t") {
			return nil, &HubFieldError{Field: prefix + "value"}
		}
	}
	return &hubWanted{fqdn: fqdn, recordType: recordType, value: value, ttl: input.TTL,
		line: hubLine(input.Line), weight: input.Weight}, nil
}

func hubRecordAuditEvent(actor HubActor, account hubAccount, mutation HubMutation, opID uuid.UUID,
	outcome hubOutcome, result, reason string) audit.Event {
	action := "dns.hub.record.create"
	switch mutation.Action {
	case "update":
		action = "dns.hub.record.update"
	case "delete":
		action = "dns.hub.record.delete"
	}
	var changes []audit.Change
	for _, field := range []struct {
		name string
		get  func(*HubRecordInput) any
	}{
		{"name", func(r *HubRecordInput) any { return r.Name }},
		{"type", func(r *HubRecordInput) any { return r.Type }},
		{"value", func(r *HubRecordInput) any { return r.Value }},
		{"line", func(r *HubRecordInput) any { return r.Line }},
		{"ttl", func(r *HubRecordInput) any { return r.TTL }},
	} {
		var before, after any
		if outcome.before != nil {
			before = field.get(outcome.before)
		}
		if outcome.after != nil {
			after = field.get(outcome.after)
		}
		if before != after {
			changes = append(changes, audit.Change{Field: field.name, Before: before, After: after})
		}
	}
	return audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: "dns_record", ResourceID: outcome.recordName, RequestID: actor.RequestID,
		Result: result, ReasonCode: reason, Changes: changes,
		Payload: map[string]any{"op_id": opID.String(), "provider_id": account.ID.String(),
			"provider_name": account.Name, "provider_type": account.ProviderType, "apex": mutation.Apex,
			"record_type": outcome.recordType, "state": outcome.result.State, "confirm_managed": mutation.ConfirmManaged},
	}
}
