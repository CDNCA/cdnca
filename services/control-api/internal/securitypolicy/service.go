package securitypolicy

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

var (
	idempotencyPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	headerNamePattern   = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]{1,128}$`)
	ja4PrefixPattern    = regexp.MustCompile(`^[a-z0-9_]{1,36}$`)
	platformCodePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service {
	return &Service{store: store}
}

func (s *Service) Create(ctx context.Context, actor Actor, request CreateRequest) (WriteResult, error) {
	if reservedLicensedWAFFields(request.Fields) {
		return WriteResult{}, ErrPermissionDenied
	}
	return s.create(ctx, actor, request)
}

func (s *Service) create(ctx context.Context, actor Actor, request CreateRequest) (WriteResult, error) {
	if err := normalizeActorAndTarget(actor, &request.TargetScopeID, &request.OwnerUserID); err != nil {
		return WriteResult{}, err
	}
	if err := normalizeSentFields(&request.Fields, true, true); err != nil || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		if err != nil {
			return WriteResult{}, err
		}
		return WriteResult{}, ErrInvalidInput
	}
	if err := s.resolveManagedRules(ctx, &request.Fields); err != nil {
		return WriteResult{}, err
	}
	if err := s.resolveSystemCCSettings(ctx, request.TargetScopeID, &request.Fields); err != nil {
		return WriteResult{}, err
	}
	if err := normalizeCCSettings(request.Fields.Kind, request.Fields.CCSettings, true); err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		TargetScopeID uuid.UUID    `json:"target_scope_id"`
		OwnerUserID   uuid.UUID    `json:"owner_user_id"`
		Fields        PolicyFields `json:"fields"`
	}{request.TargetScopeID, request.OwnerUserID, request.Fields})
	if err != nil {
		return WriteResult{}, err
	}
	// After the digest (it covers what the client sent, like update's).
	if request.Fields.Kind == KindCC {
		if err := s.applyOwnerCCDefaults(ctx, request.TargetScopeID, request.OwnerUserID, &request.Fields); err != nil {
			return WriteResult{}, err
		}
	}
	return s.store.Create(ctx, actor, request, digest)
}

// applyOwnerCCDefaults fills the 黑名单时间 / 白名单时间 a new CC policy left
// out from its owner's 网站列表 > 默认设置 (global rows; a policy is a library
// of no site group), as custom values. Without such defaults the policy keeps
// each rule's own values, as before.
func (s *Service) applyOwnerCCDefaults(ctx context.Context, scopeID, ownerID uuid.UUID, fields *PolicyFields) error {
	settings := fields.CCSettings
	if settings != nil && settings.BanSeconds != nil && settings.PassSeconds != nil {
		return nil
	}
	ban, pass, err := s.store.OwnerCCDefaults(ctx, scopeID, ownerID)
	if err != nil {
		return err
	}
	return withOwnerCCDurations(fields, ban, pass)
}

// withOwnerCCDurations sets the durations fields left out to the owner's
// defaults (0: none) as custom values.
func withOwnerCCDurations(fields *PolicyFields, ban, pass int) error {
	settings := fields.CCSettings
	if ban == 0 && pass == 0 || settings != nil && settings.BanSeconds != nil && settings.PassSeconds != nil {
		return nil
	}
	next := cloneCCSettings(settings)
	if next == nil {
		next = &CCSettings{}
	}
	if next.BanSeconds == nil && ban != 0 {
		next.BanSeconds = &CCDuration{Mode: CCSettingCustom, Seconds: ban}
	}
	if next.PassSeconds == nil && pass != 0 {
		next.PassSeconds = &CCDuration{Mode: CCSettingCustom, Seconds: pass}
	}
	// The sent settings already passed: a refusal is of the owner's defaults.
	if err := normalizeCCSettings(KindCC, next, true); err != nil {
		return unlocated(err)
	}
	fields.CCSettings = next
	return nil
}

func (s *Service) Update(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if reservedLicensedWAFFields(request.Fields) {
		return WriteResult{}, ErrPermissionDenied
	}
	return s.update(ctx, actor, request)
}

func (s *Service) update(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	// The idempotency digest covers what the client sent; the quick block
	// rules re-derived below depend on stored state.
	sent, err := digestRequest(struct {
		ID       uuid.UUID    `json:"id"`
		Revision int64        `json:"revision"`
		Fields   PolicyFields `json:"fields"`
	}{request.ID, request.ExpectedRevision, request.Fields})
	if err != nil {
		return WriteResult{}, err
	}
	// Invalid input fails before any read; the quick block rules (reserved
	// IDs) are not the client's to validate.
	precheck := request.Fields
	precheck.Rules = MergeQuickBlockRules(request.ID, cloneRules(request.Fields.Rules), nil)
	// Sent quick block rules are dropped: rules[n] would then not be as sent.
	dropped := len(precheck.Rules) != len(request.Fields.Rules)
	if len(precheck.Rules) > 0 || strings.TrimSpace(precheck.Kind) != KindWAF {
		if err := normalizeSentFields(&precheck, false, true); err != nil {
			if dropped {
				err = unlocatedRules(err)
			}
			return WriteResult{}, err
		}
	}
	if err := s.applyStoredQuickBlock(ctx, actor, &request); err != nil {
		return WriteResult{}, err
	}
	// The rules now include the stored quick block rules.
	if err := normalizeSentFields(&request.Fields, false, true); err != nil {
		return WriteResult{}, unlocatedRules(err)
	}
	if err := s.resolveManagedRules(ctx, &request.Fields); err != nil {
		return WriteResult{}, err
	}
	if UsesSystemCCSettings(request.Fields.CCSettings) {
		current, err := s.store.Get(ctx, actor, request.ID)
		if err != nil {
			return WriteResult{}, err
		}
		if err := s.resolveSystemCCSettings(ctx, current.ScopeID, &request.Fields); err != nil {
			return WriteResult{}, err
		}
	}
	if err := normalizeCCSettings(request.Fields.Kind, request.Fields.CCSettings, false); err != nil {
		return WriteResult{}, err
	}
	return s.store.Update(ctx, actor, request, sent)
}

// applyStoredQuickBlock replaces whatever the request sent under the
// policy's reserved quick block rule IDs with the rules of the stored
// switches (quick_block.go): the policy editor cannot change them. A policy
// whose quick block is on stays a default-allow WAF policy. A stale
// ExpectedRevision is left to the store's revision check (and replay).
func (s *Service) applyStoredQuickBlock(ctx context.Context, actor Actor, request *UpdateRequest) error {
	current, err := s.store.Get(ctx, actor, request.ID)
	if err != nil {
		return err
	}
	var block *QuickBlock
	if current.Revision == request.ExpectedRevision && current.QuickBlock != nil && current.QuickBlock.Active() {
		block = current.QuickBlock
		if strings.TrimSpace(request.Fields.Kind) != KindWAF || strings.TrimSpace(request.Fields.DefaultAction) != ActionAllow {
			return ErrQuickBlockUnsupported
		}
	}
	request.Fields.Rules = MergeQuickBlockRules(request.ID, request.Fields.Rules, block)
	return nil
}

// SetQuickBlock replaces a WAF policy's quick block switches and the
// system-managed rules they expand to (one new policy version). Turning any
// block on needs the control plane's verified IP intelligence library;
// publishing still needs every target node to have loaded it (edgepublish).
func (s *Service) SetQuickBlock(ctx context.Context, actor Actor, request QuickBlockRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if err := NormalizeQuickBlock(&request.QuickBlock); err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		ID         uuid.UUID  `json:"id"`
		Revision   int64      `json:"revision"`
		QuickBlock QuickBlock `json:"quick_block"`
	}{request.ID, request.ExpectedRevision, request.QuickBlock})
	if err != nil {
		return WriteResult{}, err
	}
	result, err := s.store.SetQuickBlock(ctx, actor, request, digest)
	if err != nil {
		return WriteResult{}, err
	}
	redact(&result.Policy, actor)
	return result, nil
}

// QuickBlockLibraryStatus reports whether the control plane holds a
// verified IP intelligence library (revision 0: none), which turning a
// quick block on requires.
func (s *Service) QuickBlockLibraryStatus(ctx context.Context, actor Actor) (uint64, error) {
	if !validActor(actor) {
		return 0, ErrInvalidInput
	}
	return s.store.ipIntelRevision(ctx, s.store.pool)
}

// quickBlockFields are current's fields with the rules of block in place of
// its quick block rules, checked as Update would store them.
func quickBlockFields(current Policy, block QuickBlock) (PolicyFields, error) {
	rules := MergeQuickBlockRules(current.ID, cloneRules(current.Rules), &block)
	if len(rules) == 0 {
		return PolicyFields{}, ErrQuickBlockLastRules
	}
	if len(rules) > 100 {
		return PolicyFields{}, ErrQuickBlockRuleBudget
	}
	fields := PolicyFields{Kind: current.Kind, Name: current.Name, Description: current.Description,
		Enabled: current.Enabled, DefaultAction: current.DefaultAction, Rules: rules,
		CCSettings: cloneCCSettings(current.CCSettings), WAFSettings: cloneWAFSettings(current.WAFSettings)}
	// The stored policy's rules, not the request's: no field.
	if err := normalizePublishableFields(&fields, false); err != nil {
		return PolicyFields{}, unlocated(err)
	}
	return fields, nil
}

func (s *Service) Delete(ctx context.Context, actor Actor, request DeleteRequest) (DeleteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return DeleteResult{}, ErrInvalidInput
	}
	return s.delete(ctx, actor, request)
}

func (s *Service) delete(ctx context.Context, actor Actor, request DeleteRequest) (DeleteResult, error) {
	digest, err := digestRequest(struct {
		ID       uuid.UUID `json:"id"`
		Revision int64     `json:"revision"`
	}{request.ID, request.ExpectedRevision})
	if err != nil {
		return DeleteResult{}, err
	}
	return s.store.Delete(ctx, actor, request, digest)
}

func (s *Service) Get(ctx context.Context, actor Actor, id uuid.UUID) (Policy, error) {
	if !validActor(actor) || id == uuid.Nil {
		return Policy{}, ErrInvalidInput
	}
	item, err := s.store.Get(ctx, actor, id)
	if err != nil {
		return Policy{}, err
	}
	redact(&item, actor)
	return item, nil
}

func (s *Service) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	filter.Kind = strings.TrimSpace(filter.Kind)
	filter.Status = strings.TrimSpace(filter.Status)
	filter.Name = strings.TrimSpace(filter.Name)
	filter.Owner = strings.TrimSpace(filter.Owner)
	if !validActor(actor) || filter.Page < 1 || filter.Page > 1_000_000 || filter.Limit < 1 || filter.Limit > 100 ||
		(filter.Kind != "" && !validKind(filter.Kind)) ||
		(filter.Status != "" && filter.Status != "enabled" && filter.Status != "disabled") ||
		utf8.RuneCountInString(filter.Name) > 128 || utf8.RuneCountInString(filter.Owner) > 128 ||
		(filter.Scope != "" && (filter.Kind != KindWAF ||
			(filter.Scope != ScopeGlobal && filter.Scope != ScopeSite && filter.Scope != ScopeSystem))) {
		return ListResult{}, ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" && filter.Owner != "" {
		return ListResult{}, ErrPermissionDenied
	}
	result, err := s.store.List(ctx, actor, filter)
	if err != nil {
		return ListResult{}, err
	}
	for index := range result.Items {
		redact(&result.Items[index], actor)
	}
	return result, nil
}

func (s *Service) Evaluate(ctx context.Context, actor Actor, id uuid.UUID, expectedRevision int64, facts RequestFacts) (Evaluation, error) {
	if expectedRevision < 1 {
		return Evaluation{}, ErrInvalidInput
	}
	policy, err := s.Get(ctx, actor, id)
	if err != nil {
		return Evaluation{}, err
	}
	if policy.Revision != expectedRevision {
		return Evaluation{}, ErrRevisionConflict
	}
	if policy.Protected {
		return Evaluation{}, ErrPermissionDenied
	}
	return evaluateAt(policy, facts, s.store.now().UTC())
}

func (s *Service) ListRawWAF(ctx context.Context, actor Actor) ([]Policy, error) {
	if !validActor(actor) {
		return nil, ErrInvalidInput
	}
	items := make([]Policy, 0)
	for page := 1; ; page++ {
		result, err := s.store.List(ctx, actor, ListFilter{Page: page, Limit: 100, Kind: KindWAF})
		if err != nil {
			return nil, err
		}
		items = append(items, result.Items...)
		if int64(len(items)) >= result.Total {
			return items, nil
		}
	}
}

// ListCustomWAFForReport returns a stable, non-protected snapshot for the
// installation-owned report channel. It never exposes licensed rule bodies.
func (s *Service) ListCustomWAFForReport(ctx context.Context) ([]json.RawMessage, error) {
	if s == nil || s.store == nil {
		return nil, ErrInvalidInput
	}
	result := make([]json.RawMessage, 0)
	for page := 1; ; page++ {
		items, err := s.store.List(ctx, Actor{ScopeKind: "platform"}, ListFilter{Page: page, Limit: 100, Kind: KindWAF})
		if err != nil {
			return nil, err
		}
		for _, item := range items.Items {
			if _, protected := licensedWAFMetadata(item); protected {
				continue
			}
			value := struct {
				ID            uuid.UUID       `json:"id"`
				ScopeID       uuid.UUID       `json:"scope_id"`
				Owner         *OwnerReference `json:"owner,omitempty"`
				Kind          string          `json:"kind"`
				Name          string          `json:"name"`
				Description   string          `json:"description"`
				Enabled       bool            `json:"enabled"`
				DefaultAction string          `json:"default_action"`
				Rules         []Rule          `json:"rules"`
				Version       int64           `json:"version"`
			}{ID: item.ID, ScopeID: item.ScopeID, Owner: item.Owner, Kind: item.Kind, Name: item.Name,
				Description: item.Description, Enabled: item.Enabled, DefaultAction: item.DefaultAction,
				Rules: cloneRules(item.Rules), Version: item.Revision}
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			result = append(result, encoded)
		}
		if int64(page*100) >= items.Total {
			return result, nil
		}
	}
}

// CustomPolicyReportItem is one tenant-created CC rule group or WAF policy
// for the forced v2 custom rule upload. Only the owner's user id leaves this
// package (hashed by the caller); licensed WAF bodies are never included.
type CustomPolicyReportItem struct {
	ID            uuid.UUID
	ScopeID       uuid.UUID
	OwnerID       uuid.UUID
	Name          string
	Description   string
	Enabled       bool
	DefaultAction string
	Rules         []Rule
	Version       int64
}

func (s *Service) ListCustomPoliciesForReport(ctx context.Context, kind string) ([]CustomPolicyReportItem, error) {
	if s == nil || s.store == nil || (kind != KindWAF && kind != KindCC) {
		return nil, ErrInvalidInput
	}
	result := make([]CustomPolicyReportItem, 0)
	for page := 1; ; page++ {
		items, err := s.store.List(ctx, Actor{ScopeKind: "platform"}, ListFilter{Page: page, Limit: 100, Kind: kind})
		if err != nil {
			return nil, err
		}
		for _, item := range items.Items {
			if _, protected := licensedWAFMetadata(item); protected {
				continue
			}
			owner := uuid.Nil
			if item.Owner != nil {
				owner = item.Owner.ID
			}
			result = append(result, CustomPolicyReportItem{ID: item.ID, ScopeID: item.ScopeID, OwnerID: owner, Name: item.Name,
				Description: item.Description, Enabled: item.Enabled, DefaultAction: item.DefaultAction,
				Rules: cloneRules(item.Rules), Version: item.Revision})
		}
		if int64(page*100) >= items.Total {
			return result, nil
		}
	}
}

func (s *Service) ListLicensedWAFSubscriptions(ctx context.Context, actor Actor) ([]LicensedWAFSubscription, error) {
	items, err := s.ListRawWAF(ctx, actor)
	if err != nil {
		return nil, err
	}
	result := make([]LicensedWAFSubscription, 0)
	for _, item := range items {
		metadata, protected := licensedWAFMetadata(item)
		if protected {
			result = append(result, LicensedWAFSubscription{PolicyID: item.ID, Revision: item.Revision, Metadata: metadata})
		}
	}
	return result, nil
}

func (s *Service) UpsertLicensedWAF(ctx context.Context, actor Actor, definition LicensedWAFDefinition, key, requestID string) (Policy, error) {
	if !validActor(actor) || actor.ScopeKind != "tenant" || !validLicensedWAFDefinition(definition) ||
		!validWriteMetadata(key, requestID) {
		return Policy{}, ErrInvalidInput
	}
	metadata := LicensedWAFMetadata{LibraryID: definition.LibraryID, Revision: definition.Revision,
		Name: definition.Name, Description: definition.Description}
	description, err := encodeLicensedWAFMetadata(metadata)
	if err != nil {
		return Policy{}, err
	}
	fields := PolicyFields{Kind: KindWAF, Name: licensedWAFStorageName(definition.LibraryID), Description: description,
		Enabled: definition.Enabled, DefaultAction: definition.DefaultAction, Rules: cloneRules(definition.Rules)}
	items, err := s.ListRawWAF(ctx, actor)
	if err != nil {
		return Policy{}, err
	}
	for _, item := range items {
		stored, protected := licensedWAFMetadata(item)
		if !protected || stored.LibraryID != definition.LibraryID {
			continue
		}
		if stored.Revision > definition.Revision {
			return Policy{}, ErrRevisionConflict
		}
		if stored.Revision == definition.Revision {
			redact(&item, actor)
			return item, nil
		}
		result, updateErr := s.update(ctx, actor, UpdateRequest{ID: item.ID, ExpectedRevision: item.Revision,
			Fields: fields, IdempotencyKey: key, RequestID: requestID, AllowProtected: true})
		if updateErr != nil {
			return Policy{}, unlocated(updateErr) // the library's rules, not a request body
		}
		redact(&result.Policy, actor)
		return result.Policy, nil
	}
	result, err := s.create(ctx, actor, CreateRequest{Fields: fields, IdempotencyKey: key, RequestID: requestID})
	if err != nil {
		return Policy{}, unlocated(err)
	}
	redact(&result.Policy, actor)
	return result.Policy, nil
}

func (s *Service) RemoveLicensedWAF(ctx context.Context, actor Actor, libraryID, key, requestID string) error {
	if !validActor(actor) || actor.ScopeKind != "tenant" || !validLicensedWAFLibraryID(libraryID) ||
		!validWriteMetadata(key, requestID) {
		return ErrInvalidInput
	}
	items, err := s.ListRawWAF(ctx, actor)
	if err != nil {
		return err
	}
	for _, item := range items {
		metadata, protected := licensedWAFMetadata(item)
		if protected && metadata.LibraryID == libraryID {
			_, err = s.delete(ctx, actor, DeleteRequest{ID: item.ID, ExpectedRevision: item.Revision,
				IdempotencyKey: key, RequestID: requestID, AllowProtected: true})
			return err
		}
	}
	return ErrNotFound
}

func normalizeActorAndTarget(actor Actor, scopeID, ownerID *uuid.UUID) error {
	if !validActor(actor) {
		return ErrInvalidInput
	}
	switch actor.ScopeKind {
	case "platform":
		if *scopeID == uuid.Nil || *ownerID == uuid.Nil {
			return ErrInvalidInput
		}
	case "tenant":
		if (*scopeID != uuid.Nil && *scopeID != actor.ScopeID) || (*ownerID != uuid.Nil && *ownerID != actor.UserID) {
			return ErrPermissionDenied
		}
		*scopeID = actor.ScopeID
		*ownerID = actor.UserID
	}
	return nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && (actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func validLicensedWAFDefinition(definition LicensedWAFDefinition) bool {
	if !validLicensedWAFLibraryID(definition.LibraryID) || definition.Revision < 1 ||
		utf8.RuneCountInString(strings.TrimSpace(definition.Name)) < 1 || utf8.RuneCountInString(definition.Name) > 128 ||
		!utf8.ValidString(definition.Description) || utf8.RuneCountInString(definition.Description) > 500 ||
		definition.DefaultAction != ActionAllow && definition.DefaultAction != ActionBlock ||
		len(definition.Rules) < 1 || len(definition.Rules) > 100 {
		return false
	}
	fields := PolicyFields{Kind: KindWAF, Name: licensedWAFStorageName(definition.LibraryID),
		Description: "licensed", Enabled: definition.Enabled, DefaultAction: definition.DefaultAction,
		Rules: cloneRules(definition.Rules)}
	return normalizePublishableFields(&fields, false) == nil
}

func validLicensedWAFLibraryID(value string) bool {
	if platformCodePattern.MatchString(value) {
		return true
	}
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func reservedLicensedWAFFields(fields PolicyFields) bool {
	return strings.HasPrefix(strings.TrimSpace(fields.Name), "@system/") ||
		strings.HasPrefix(strings.TrimSpace(fields.Description), licensedWAFDescriptionPrefix)
}

func licensedWAFStorageName(libraryID string) string { return "@system/" + libraryID }

func encodeLicensedWAFMetadata(metadata LicensedWAFMetadata) (string, error) {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	value := licensedWAFDescriptionPrefix + base64.RawURLEncoding.EncodeToString(encoded)
	if utf8.RuneCountInString(value) > 1000 {
		return "", ErrInvalidInput
	}
	return value, nil
}

func licensedWAFMetadata(policy Policy) (LicensedWAFMetadata, bool) {
	if policy.Kind != KindWAF || !strings.HasPrefix(policy.Description, licensedWAFDescriptionPrefix) {
		return LicensedWAFMetadata{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(policy.Description, licensedWAFDescriptionPrefix))
	if err != nil {
		return LicensedWAFMetadata{}, false
	}
	var metadata LicensedWAFMetadata
	if json.Unmarshal(raw, &metadata) != nil || !validLicensedWAFLibraryID(metadata.LibraryID) ||
		metadata.Revision < 1 || strings.TrimSpace(metadata.Name) == "" {
		return LicensedWAFMetadata{}, false
	}
	return metadata, true
}

func normalizeFields(fields *PolicyFields, create bool) error {
	fields.Kind = strings.TrimSpace(fields.Kind)
	fields.Name = strings.TrimSpace(fields.Name)
	fields.Description = strings.TrimSpace(fields.Description)
	fields.DefaultAction = strings.TrimSpace(fields.DefaultAction)
	if fields.ACLImport != "" {
		if fields.Kind != KindACL || len(fields.Rules) != 0 {
			return refuse("acl_import", fielderr.Invalid)
		}
		rules, err := ParseACLImport(fields.ACLImport)
		if err != nil {
			return err
		}
		fields.Rules = rules
		fields.ACLImport = ""
	}
	nameLength, descriptionLength := utf8.RuneCountInString(fields.Name), utf8.RuneCountInString(fields.Description)
	switch {
	case !validKind(fields.Kind):
		return refuse("kind", fielderr.Invalid)
	case !validDecision(fields.DefaultAction):
		return refuse("default_action", fielderr.Invalid)
	case nameLength < 1:
		return refuse("name", fielderr.Required)
	case nameLength > 128:
		return refuse("name", fielderr.TooLong)
	case !utf8.ValidString(fields.Description):
		return refuse("description", fielderr.InvalidFormat)
	case descriptionLength > 1000:
		return refuse("description", fielderr.TooLong)
	case len(fields.Rules) < 1:
		return refuse("rules", fielderr.Required)
	case len(fields.Rules) > 100:
		return refuse("rules", fielderr.OutOfRange)
	}
	seenIDs := make(map[uuid.UUID]struct{}, len(fields.Rules))
	managed := 0
	for index := range fields.Rules {
		path := indexed("rules", index)
		if err := normalizeRule(&fields.Rules[index]); err != nil {
			return fielderr.Within(err, path)
		}
		if err := normalizeCountBy(fields.Kind, &fields.Rules[index]); err != nil {
			return fielderr.Within(err, path)
		}
		if fields.Rules[index].Action == ActionManagedWAF {
			if managed++; managed > 1 || fields.Kind != KindWAF {
				return refuse(path+".action", fielderr.Invalid)
			}
		}
		for conditionIndex, condition := range fields.Rules[index].Conditions {
			if isSEC11CountField(condition.Field) && fields.Kind != KindCC {
				return refuse(path+"."+indexed("conditions", conditionIndex)+".field", fielderr.Invalid)
			}
		}
		if fields.Kind != KindACL && fields.Rules[index].Comment != "" {
			return refuse(path+".comment", fielderr.Invalid)
		}
		if fields.Kind != KindACL && fields.Rules[index].ExpiresAt != "" {
			return refuse(path+".expires_at", fielderr.Invalid)
		}
		// ban and the WAF challenge are WAF rule actions; a WAF policy's
		// challenge is always the WAF challenge.
		rule := fields.Rules[index]
		if rule.Action == ActionBan && fields.Kind != KindWAF || rule.ActionConfig.WAFChallenge != nil && fields.Kind != KindWAF ||
			fields.Kind == KindWAF && rule.Action == ActionChallenge && rule.ActionConfig.WAFChallenge == nil {
			return refuse(path+".action", fielderr.Invalid)
		}
		if fields.Rules[index].ID == uuid.Nil {
			continue
		}
		if create {
			return refuse(path+".id", fielderr.Invalid)
		}
		if _, duplicate := seenIDs[fields.Rules[index].ID]; duplicate {
			return refuse(path+".id", fielderr.Duplicate)
		}
		seenIDs[fields.Rules[index].ID] = struct{}{}
	}
	settings, err := normalizeWAFSettings(fields.Kind, fields.WAFSettings)
	if err != nil {
		return err
	}
	fields.WAFSettings = settings
	sortRules(fields.Rules)
	return nil
}

// ValidatePublishablePolicy applies the same gate Create/Update use, so
// generated policies (system rule catalog expansion, audits) cannot drift
// from what the API would accept.
func ValidatePublishablePolicy(policy Policy) error {
	fields := PolicyFields{Kind: policy.Kind, Name: policy.Name, Description: policy.Description,
		Enabled: policy.Enabled, DefaultAction: policy.DefaultAction, Rules: cloneRules(policy.Rules),
		WAFSettings: cloneWAFSettings(policy.WAFSettings)}
	return unlocated(normalizePublishableFields(&fields, false))
}

// NormalizePublishableWAFRules returns rules as Create/Update would store
// them in a WAF policy whose default is allow (values sorted, header keys
// lower-cased, rules ordered), or ErrInvalidInput when the gate refuses them.
func NormalizePublishableWAFRules(rules []Rule) ([]Rule, error) {
	fields := PolicyFields{Kind: KindWAF, Name: "normalize", Enabled: true, DefaultAction: ActionAllow, Rules: cloneRules(rules)}
	if err := normalizePublishableFields(&fields, false); err != nil {
		return nil, unlocated(err)
	}
	return fields.Rules, nil
}

// normalizePublishableFields is normalizeFields plus the node runtime gate
// (ACL policies: validateACLFields follows). A refused rule is named as sent:
// rules[n] in request order (the rules are sorted by priority before the
// runtime gate); a refused imported rule names acl_import.
func normalizePublishableFields(fields *PolicyFields, create bool) error {
	return normalizeSentFields(fields, create, false)
}

// normalizeSentFields: normalizePublishableFields, and with acl the ACL
// checks (validateACLFields) under the same field naming.
func normalizeSentFields(fields *PolicyFields, create, acl bool) error {
	imported := fields.ACLImport != ""
	order := requestOrder(fields.Rules)
	err := normalizePublishableSorted(fields, create, order)
	if err == nil && acl && fields.Kind == KindACL {
		if len(order) != len(fields.Rules) {
			order = nil
		}
		err = validateACLFieldsInOrder(fields.Rules, order)
	}
	if located, ok := fielderr.As(err); ok && imported && strings.HasPrefix(located.Field, "rules") {
		return refuse("acl_import", located.Reason)
	}
	return err
}

func normalizePublishableSorted(fields *PolicyFields, create bool, order []int) error {
	if err := normalizeFields(fields, create); err != nil {
		return err
	}
	if len(order) != len(fields.Rules) {
		order = nil // acl_import: the rules are the import's
	}
	if fields.Kind == KindACL {
		return nil
	}
	for position, rule := range fields.Rules {
		path := rulePath(order, position)
		if fields.Kind == KindWAF && len(rule.Conditions) > MaxWAFRuleConditions {
			return refuse(path+".conditions", fielderr.OutOfRange)
		}
		seen := make(map[string]struct{}, len(rule.Conditions))
		for conditionIndex, condition := range rule.Conditions {
			conditionPath := path + "." + indexed("conditions", conditionIndex)
			if !runtimeConditionSupported(fields.Kind, condition) {
				return refuse(conditionPath+".operator", fielderr.Invalid)
			}
			// CC rules may repeat client IP and header conditions (all must
			// hold, NF27); everything else is one condition per field.
			if fields.Kind == KindCC && ccRepeatableField(condition.Field) {
				continue
			}
			// WAF content conditions are inspect clauses, ANDed on the node:
			// args key=a and args key=b, or contains and not_contains.
			if fields.Kind == KindWAF && wafRepeatableCondition(condition) {
				continue
			}
			if _, duplicate := seen[condition.Field]; duplicate {
				return refuse(conditionPath+".field", fielderr.Duplicate)
			}
			seen[condition.Field] = struct{}{}
		}
	}
	return nil
}

func runtimeConditionSupported(kind string, condition Condition) bool {
	supported := map[string]map[string][]string{
		KindWAF: {
			"client_ip": {"ip_in_cidr"},
			"method":    {"equals"},
			"port":      {"number_eq"},
			// a named IP list (security_ip_lists id),
			// expanded at publication; W1 content_type / http_version. Both
			// need CAPABILITY_NAME_WAF v4.
			"ip_list": ipListOperators,
			// Content fields: cdnca_waf inspect clauses (edgeconfig.WAFInspect).
			"path":              wafContentOperators,
			"header":            wafContentOperators,
			"args":              wafContentOperators,
			"query":             wafContentOperators,
			"body":              wafContentOperators,
			"request_uri":       wafContentOperators,
			"cookie":            wafContentOperators,
			"user_agent":        wafContentOperators,
			"referer":           wafContentOperators,
			"upload_filename":   wafContentOperators,
			"upload_extension":  wafContentOperators,
			"header_names":      wafContentOperators,
			"content_type":      wafContentOperators,
			"http_version":      wafHTTPVersionOperators,
			"request_length":    wafLengthOperators,
			"body_length":       wafLengthOperators,
			"uri_length":        wafLengthOperators,
			"header_max_length": wafLengthOperators,
			"header_count":      wafLengthOperators,
			"arg_count":         wafLengthOperators,

			// multipart part names / count / longest
			// field; need CAPABILITY_NAME_WAF v5.
			"multipart_field_names":      wafContentOperators,
			"multipart_part_count":       wafLengthOperators,
			"multipart_field_max_length": wafLengthOperators,

			// $cdnca_ja4 set by the native JA4 module; needs CAPABILITY_NAME_JA4,
			// not_in also CAPABILITY_NAME_WAF_JA4_NEGATION.
			"ja4": {"equals", "in", "not_in"},
			// Looked up in the node's signed IP intelligence library
			// (cdnca_iplib); needs CAPABILITY_NAME_IP_INTEL v2.
			"carrier":  {"equals", "not_equals", "in", "not_in"},
			"ip_tag":   {"equals", "not_equals", "in", "not_in"},
			"asn":      {"number_eq", "equals", "not_equals", "in", "not_in"},
			"country":  {"equals", "not_equals", "in", "not_in"},
			"province": {"equals", "not_equals", "in", "not_in"},
			"city":     {"equals", "not_equals", "in", "not_in"},
		},
		KindCC: {
			// ip_not_in_cidr, header, user_agent, referer: CC API v6.
			"client_ip":            {"equals", "ip_in_cidr", "ip_not_in_cidr"},
			"header":               {"equals", "prefix", "contains", "regex"},
			"user_agent":           {"equals", "prefix", "contains", "regex"},
			"referer":              {"equals", "prefix", "contains", "regex"},
			"host":                 {"equals"},
			"path":                 {"equals", "prefix", "contains"},
			"method":               {"equals"},
			"port":                 {"number_eq"},
			"distinct_user_agents": {"number_gte"},
			"status_404_count":     {"number_gte"},
			// CC API v7: $cdnca_ja4 is one of the values.
			"ja4": {"equals", "in"},
		},
	}
	return slices.Contains(supported[kind][condition.Field], condition.Operator)
}

// MaxWAFRuleConditions bounds the conditions of one WAF rule
// (edgeconfig.MaxWAFInspectPerRule inspect clauses at most).
const MaxWAFRuleConditions = 8

// wafRepeatableCondition: a WAF condition the node runs as an inspect clause
// (content field, not a native path equals / prefix or header equals).
func wafRepeatableCondition(condition Condition) bool {
	_, inspect, _ := edgeconfig.WAFInspectPolicyCondition(condition.Field, condition.Operator, condition.Key, condition.Values,
		condition.Filters, condition.BodyOverflow)
	return inspect
}

// ccRepeatableField: CC conditions on these fields may appear more than once
// in a rule (CC API v6 client_ip / headers lists).
func ccRepeatableField(field string) bool {
	return field == "client_ip" || field == "header" || field == "user_agent" || field == "referer"
}

// ValidateACLRules applies the ordering and overlap rules ACL Create/Update
// enforce on top of ValidatePublishablePolicy (marketsupply pre-checks).
func ValidateACLRules(rules []Rule) error { return validateACLFields(rules) }

// validateACLFields checks rules the client did not send as listed (no field).
func validateACLFields(rules []Rule) error { return unlocated(validateACLFieldsInOrder(rules, nil)) }

// validateACLFieldsInOrder checks ACL rules (sorted by priority); a refusal
// names rules[n] with n as sent (rulePath).
func validateACLFieldsInOrder(rules []Rule, order []int) error {
	seen := make(map[string]struct{}, len(rules))
	terminal := make([]netip.Prefix, 0, len(rules))
	maxAllowPriority, minBlockPriority := 0, int(^uint(0)>>1)
	allowPath := ""
	for position, rule := range rules {
		path := rulePath(order, position)
		if rule.Action != ActionAllow && rule.Action != ActionBlock {
			return refuse(path+".action", fielderr.Invalid)
		}
		if len(rule.Conditions) != 1 {
			return refuse(path+".conditions", fielderr.Invalid)
		}
		condition := rule.Conditions[0]
		valuesPath := path + ".conditions[0].values"
		if condition.Field != "client_ip" || condition.Operator != "ip_in_cidr" || condition.Key != "" {
			return refuse(path+".conditions[0].field", fielderr.Invalid)
		}
		if len(condition.Values) != 1 {
			return refuse(valuesPath, fielderr.Invalid)
		}
		prefix, err := netip.ParsePrefix(condition.Values[0])
		if err != nil || prefix != prefix.Masked() {
			return refuse(valuesPath, fielderr.InvalidFormat)
		}
		key := prefix.String()
		if _, duplicate := seen[key]; duplicate {
			return refuse(valuesPath, fielderr.Duplicate)
		}
		seen[key] = struct{}{}
		if rule.Action == ActionAllow && rule.Priority > maxAllowPriority {
			maxAllowPriority, allowPath = rule.Priority, path
		}
		if rule.Action == ActionBlock && rule.Priority < minBlockPriority {
			minBlockPriority = rule.Priority
		}
		// A network already covered by an earlier terminal rule never runs.
		for _, previous := range terminal {
			if previous.Addr().BitLen() == prefix.Addr().BitLen() &&
				previous.Bits() <= prefix.Bits() && previous.Contains(prefix.Addr()) {
				return refuse(valuesPath, fielderr.Duplicate)
			}
		}
		if rule.Flow == FlowStop {
			terminal = append(terminal, prefix)
		}
	}
	if maxAllowPriority != 0 && minBlockPriority != int(^uint(0)>>1) && maxAllowPriority >= minBlockPriority {
		return refuse(allowPath+".priority", fielderr.Invalid)
	}
	return nil
}

func normalizeRule(rule *Rule) error {
	rawComment := rule.Comment
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Action = strings.TrimSpace(rule.Action)
	rule.Flow = strings.TrimSpace(rule.Flow)
	rule.Comment = strings.TrimSpace(rule.Comment)
	nameLength := utf8.RuneCountInString(rule.Name)
	switch {
	case nameLength < 1:
		return refuse("name", fielderr.Required)
	case nameLength > 128:
		return refuse("name", fielderr.TooLong)
	case rule.Priority < 1 || rule.Priority > 1_000_000:
		return refuse("priority", fielderr.OutOfRange)
	case !validAction(rule.Action):
		return refuse("action", fielderr.Invalid)
	case rule.Flow != FlowContinue && rule.Flow != FlowStop:
		return refuse("flow", fielderr.Invalid)
	case len(rule.Conditions) > 16:
		return refuse("conditions", fielderr.OutOfRange)
	case rule.Action == ActionManagedWAF && len(rule.Conditions) != 0:
		return refuse("conditions", fielderr.Invalid)
	case rule.Action != ActionManagedWAF && len(rule.Conditions) == 0:
		return refuse("conditions", fielderr.Required)
	case rawComment != "" && !validACLComment(rule.Comment):
		return refuse("comment", fielderr.Invalid)
	case rule.ExpiresAt != "" && !validACLExpiry(rule.ExpiresAt):
		return refuse("expires_at", fielderr.InvalidFormat)
	}
	if err := normalizeActionConfig(rule); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(rule.Conditions))
	countFields := make(map[string]struct{}, 2)
	for index := range rule.Conditions {
		path := indexed("conditions", index)
		if err := normalizeCondition(&rule.Conditions[index]); err != nil {
			return fielderr.Within(err, path)
		}
		if isSEC11CountField(rule.Conditions[index].Field) {
			limit := rule.ActionConfig.RateLimit
			if rule.Action != ActionRateLimit || limit == nil ||
				limit.Algorithm != "" && limit.Algorithm != "fixed_window" {
				return refuse(path+".field", fielderr.Invalid)
			}
			if _, duplicate := countFields[rule.Conditions[index].Field]; duplicate {
				return refuse(path+".field", fielderr.Duplicate)
			}
			countFields[rule.Conditions[index].Field] = struct{}{}
		}
		encoded, _ := json.Marshal(rule.Conditions[index])
		if _, duplicate := seen[string(encoded)]; duplicate {
			return refuse(path, fielderr.Duplicate)
		}
		seen[string(encoded)] = struct{}{}
	}
	return nil
}

// normalizeConditionFilters checks a condition's filters and body overflow:
// only WAF content fields take filters (length last, and exactly with a
// number_* operator on a text field); a number field takes none; only body
// fields take body_overflow "match".
func normalizeConditionFilters(condition *Condition) error {
	number := strings.HasPrefix(condition.Operator, "number_")
	numberField := slices.Contains(wafNumberFields, condition.Field)
	content := numberField || slices.Contains(wafContentFieldNames, condition.Field)
	if len(condition.Filters) == 0 {
		condition.Filters = nil
	}
	if !content && condition.BodyOverflow != "" {
		return refuse("body_overflow", fielderr.Invalid)
	}
	if !content && len(condition.Filters) != 0 || (numberField || condition.Field == "http_version") && len(condition.Filters) != 0 {
		return refuse("filters", fielderr.Invalid)
	}
	if len(condition.Filters) > 4 {
		return refuse("filters", fielderr.OutOfRange)
	}
	for index, filter := range condition.Filters {
		if !slices.Contains(wafFilters, filter) || filter == "length" && index != len(condition.Filters)-1 {
			return refuse(indexed("filters", index), fielderr.Invalid)
		}
	}
	length := len(condition.Filters) > 0 && condition.Filters[len(condition.Filters)-1] == "length"
	if content && number != (numberField || length) {
		return refuse("operator", fielderr.Invalid)
	}
	if condition.BodyOverflow != "" && (condition.BodyOverflow != "match" || !slices.Contains(wafBodyFields, condition.Field)) {
		return refuse("body_overflow", fielderr.Invalid)
	}
	return nil
}

// wafContentFieldNames are the text fields edgeconfig.WAFInspect reads.
var wafContentFieldNames = []string{"args", "query", "body", "request_uri", "path", "header", "cookie", "user_agent", "referer",
	"upload_filename", "upload_extension", "header_names", "content_type", "http_version", "multipart_field_names"}

func validACLExpiry(value string) bool {
	const layout = "2006-01-02T15:04:05Z"
	parsed, err := time.Parse(layout, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Unix() >= 0 && parsed.Format(layout) == value
}

// normalizeActionConfig checks the action_config the action carries; a
// config another action owns names action_config, a bad value its field.
func normalizeActionConfig(rule *Rule) error {
	config := rule.ActionConfig
	switch rule.Action {
	case ActionRateLimit:
		if config.RateLimit == nil {
			return refuse("action_config.rate_limit", fielderr.Required)
		}
		if config.Challenge != nil {
			return refuse("action_config", fielderr.Invalid)
		}
		if err := normalizeRateLimitConfig(config.RateLimit); err != nil {
			return fielderr.Within(err, "action_config.rate_limit")
		}
	case ActionChallenge:
		if config.WAFChallenge != nil {
			if config.Challenge != nil || config.RateLimit != nil || config.ManagedWAF != nil {
				return refuse("action_config", fielderr.Invalid)
			}
			break
		}
		if config.Challenge == nil {
			return refuse("action_config.challenge", fielderr.Required)
		}
		if config.RateLimit != nil || config.ManagedWAF != nil {
			return refuse("action_config", fielderr.Invalid)
		}
		if err := checkChallengeConfig(*config.Challenge); err != nil {
			return fielderr.Within(err, "action_config.challenge")
		}
	case ActionManagedWAF:
		if config.ManagedWAF == nil {
			return refuse("action_config.managed_waf", fielderr.Required)
		}
		if config.RateLimit != nil || config.Challenge != nil {
			return refuse("action_config", fielderr.Invalid)
		}
		if rule.Flow != FlowContinue {
			return refuse("flow", fielderr.Invalid)
		}
		if ValidateManagedWAF(*config.ManagedWAF) != nil {
			return refuse("action_config.managed_waf", fielderr.Invalid)
		}
	default:
		if config.RateLimit != nil || config.Challenge != nil || config.ManagedWAF != nil {
			return refuse("action_config", fielderr.Invalid)
		}
	}
	// WAF ban carries waf_ban; a WAF challenge carries waf_challenge instead
	// of the CC challenge (normalizeFields checks the kind).
	switch {
	case rule.Action == ActionBan && config.WAFBan == nil:
		return refuse("action_config.waf_ban", fielderr.Required)
	case rule.Action != ActionBan && config.WAFBan != nil:
		return refuse("action_config", fielderr.Invalid)
	case config.WAFBan != nil && !validWAFBanConfig(config.WAFBan):
		return refuse("action_config.waf_ban.ban_seconds", fielderr.OutOfRange)
	case config.WAFChallenge != nil && rule.Action != ActionChallenge:
		return refuse("action_config", fielderr.Invalid)
	case config.WAFChallenge != nil && !validWAFChallengeAction(config.WAFChallenge):
		return outOfRange(
			bound{"action_config.waf_challenge.pass_seconds", within(config.WAFChallenge.PassSeconds, 60, 86_400)},
			bound{"action_config.waf_challenge.pow_bits", within(config.WAFChallenge.PowBits, 8, 24)})
	}
	return nil
}

func normalizeRateLimitConfig(config *RateLimitConfig) error {
	if config == nil {
		return ErrInvalidInput
	}
	switch config.Algorithm {
	case "":
		if err := checkFixedWindow(config); err != nil {
			return err
		}
		if config.ResponseAction != "" {
			return refuse("response_action", fielderr.Invalid)
		}
		if config.BanSeconds != 0 {
			return refuse("ban_seconds", fielderr.Invalid)
		}
		if config.Adaptive != nil {
			return refuse("adaptive", fielderr.Invalid)
		}
		return nil
	case "fixed_window":
		if err := checkFixedWindow(config); err != nil {
			return err
		}
		if config.Adaptive != nil {
			return refuse("adaptive", fielderr.Invalid)
		}
	case "leaky_bucket", "adaptive":
		switch {
		case config.WindowSeconds != 0:
			return refuse("window_seconds", fielderr.Invalid)
		case config.MaxRequests != 0:
			return refuse("max_requests", fielderr.Invalid)
		case config.MaxPerURI != 0:
			return refuse("max_requests_per_uri", fielderr.Invalid)
		}
		if err := outOfRange(bound{"rate_per_second", within(config.RatePerSecond, 1, 1_000_000)},
			bound{"burst", within(config.Burst, 1, 1_000_000)}); err != nil {
			return err
		}
		if config.Algorithm == "leaky_bucket" && config.Adaptive != nil {
			return refuse("adaptive", fielderr.Invalid)
		}
		if config.Algorithm == "adaptive" {
			if err := normalizeAdaptiveRateLimit(config); err != nil {
				return fielderr.Within(err, "adaptive")
			}
		}
	default:
		return refuse("algorithm", fielderr.Invalid)
	}
	if config.ResponseAction == "" {
		config.ResponseAction = "reject_429"
	}
	switch config.ResponseAction {
	case "reject_429", "log":
		if config.BanSeconds != 0 {
			return refuse("ban_seconds", fielderr.Invalid)
		}
	case "temporary_ban":
		if !within(config.BanSeconds, 1, 86_400) {
			return refuse("ban_seconds", fielderr.OutOfRange)
		}
	default:
		return refuse("response_action", fielderr.Invalid)
	}
	return nil
}

// checkFixedWindow refuses the first fixed window field validFixedWindow
// does not accept.
func checkFixedWindow(config *RateLimitConfig) error {
	if validFixedWindow(config) {
		return nil
	}
	if config.RatePerSecond != 0 {
		return refuse("rate_per_second", fielderr.Invalid)
	}
	if config.Burst != 0 {
		return refuse("burst", fielderr.Invalid)
	}
	return outOfRange(bound{"window_seconds", within(config.WindowSeconds, 1, 3600)},
		bound{"max_requests", within(config.MaxRequests, 1, 1_000_000)},
		bound{"max_requests_per_uri", within(config.MaxPerURI, 0, 1_000_000)})
}

func validFixedWindow(config *RateLimitConfig) bool {
	return config.WindowSeconds >= 1 && config.WindowSeconds <= 3600 &&
		config.MaxRequests >= 1 && config.MaxRequests <= 1_000_000 &&
		config.MaxPerURI >= 0 && config.MaxPerURI <= 1_000_000 &&
		config.RatePerSecond == 0 && config.Burst == 0
}

// ChallengeTypes lists the verification pages the node can serve.
var ChallengeTypes = []string{"js", "five_second", "click", "simple_click", "slider", "simple_slider", "captcha", "rotate_image", "redirect"}

// checkChallengeConfig refuses the first challenge field the node could not
// serve (field names as in ChallengeConfig's JSON).
func checkChallengeConfig(config ChallengeConfig) error {
	optional := func(value, minimum, maximum int) bool { return value == 0 || within(value, minimum, maximum) }
	// pair: both of a window and its count are set, or neither; the unset one is named.
	pair := func(window, requests int, windowField, requestsField string) error {
		if window != 0 && requests == 0 {
			return refuse(requestsField, fielderr.Required)
		}
		if window == 0 && requests != 0 {
			return refuse(windowField, fielderr.Required)
		}
		return nil
	}
	switch {
	case !slices.Contains(ChallengeTypes, config.Type):
		return refuse("type", fielderr.Invalid)
	case config.LogOnly && config.BanSeconds != 0:
		return refuse("ban_seconds", fielderr.Invalid)
	case !config.LogOnly && config.BanSeconds == 0:
		return refuse("ban_seconds", fielderr.Required)
	case config.Type == "redirect" && config.PowBits != 0:
		return refuse("pow_bits", fielderr.Invalid)
	case config.Type == "five_second" && config.DelaySeconds == 0:
		return refuse("delay_seconds", fielderr.Required)
	case config.Type != "five_second" && config.DelaySeconds != 0:
		return refuse("delay_seconds", fielderr.Invalid)
	}
	if err := outOfRange(
		bound{"failure_window_seconds", within(config.FailureWindowSeconds, 1, 86_400)},
		bound{"max_failures", within(config.MaxFailures, 1, 1000)},
		bound{"pass_seconds", within(config.PassSeconds, 60, 7*86_400)},
		bound{"ban_seconds", optional(config.BanSeconds, 1, 86_400)},
		bound{"pow_bits", config.Type == "redirect" || within(config.PowBits, 8, 26)},
		bound{"delay_seconds", optional(config.DelaySeconds, 1, 30)},
		bound{"challenge_seconds", within(config.ChallengeSeconds, 30, 3600)},
		bound{"bind_ipv4_prefix", within(config.BindIPv4Prefix, 8, 32)},
		bound{"bind_ipv6_prefix", within(config.BindIPv6Prefix, 32, 128)},
		// The signing key must outlive a pass.
		bound{"key_rotate_seconds", within(config.KeyRotateSeconds, config.PassSeconds, 30*86_400)},
		bound{"trigger_window_seconds", optional(config.TriggerWindowSeconds, 1, 3600)},
		bound{"trigger_max_requests", optional(config.TriggerMaxRequests, 1, 1_000_000)},
		bound{"pass_window_seconds", optional(config.PassWindowSeconds, 1, 3600)},
		bound{"pass_max_requests", optional(config.PassMaxRequests, 1, 1_000_000)},
		bound{"pass_max_requests_per_uri", optional(config.PassMaxRequestsPerURI, 1, 1_000_000)},
	); err != nil {
		return err
	}
	if err := pair(config.TriggerWindowSeconds, config.TriggerMaxRequests, "trigger_window_seconds", "trigger_max_requests"); err != nil {
		return err
	}
	if err := pair(config.PassWindowSeconds, config.PassMaxRequests, "pass_window_seconds", "pass_max_requests"); err != nil {
		return err
	}
	if config.PassMaxRequestsPerURI != 0 && config.PassWindowSeconds == 0 {
		return refuse("pass_window_seconds", fielderr.Required)
	}
	return nil
}

func normalizeAdaptiveRateLimit(config *RateLimitConfig) error {
	adaptive := config.Adaptive
	if adaptive == nil {
		return ErrInvalidInput
	}
	if adaptive.Fallback == "" {
		adaptive.Fallback = "static"
	}
	if adaptive.Fallback != "static" {
		return refuse("fallback", fielderr.Invalid)
	}
	switch adaptive.Profile {
	case "simple":
		if adaptive.Enforcement != "shadow" {
			return refuse("enforcement", fielderr.Invalid)
		}
		// The simple profile sets every tuning value itself.
		if adaptive.AutoApproved || adaptive.Frozen ||
			adaptive.MinSamples != 0 || adaptive.MaxSamples != 0 || adaptive.SampleFreshnessSeconds != 0 ||
			adaptive.EWMAAlphaPermille != 0 || adaptive.MADMultiplierMilli != 0 ||
			adaptive.MinRatePerSecond != 0 || adaptive.MaxRatePerSecond != 0 ||
			adaptive.MinBurst != 0 || adaptive.MaxBurst != 0 || adaptive.MaxStepPermille != 0 ||
			adaptive.HysteresisPermille != 0 || adaptive.CooldownSeconds != 0 || adaptive.MaxGroups != 0 {
			return refuse("profile", fielderr.Invalid)
		}
		adaptive.MinSamples, adaptive.MaxSamples, adaptive.SampleFreshnessSeconds = 8, 64, 30
		adaptive.EWMAAlphaPermille, adaptive.MADMultiplierMilli = 250, 2500
		adaptive.MinRatePerSecond, adaptive.MaxRatePerSecond = 1, config.RatePerSecond
		adaptive.MinBurst, adaptive.MaxBurst = 1, config.Burst
		adaptive.MaxStepPermille, adaptive.HysteresisPermille = 100, 50
		adaptive.CooldownSeconds, adaptive.MaxGroups = 10, 1000
	case "expert":
		if adaptive.Enforcement != "shadow" && adaptive.Enforcement != "auto" {
			return refuse("enforcement", fielderr.Invalid)
		}
		if adaptive.Enforcement == "auto" != adaptive.AutoApproved {
			return refuse("auto_approved", fielderr.Invalid)
		}
	default:
		return refuse("profile", fielderr.Invalid)
	}
	return outOfRange(
		bound{"min_samples", adaptive.MinSamples >= 3},
		bound{"max_samples", adaptive.MaxSamples >= adaptive.MinSamples && adaptive.MaxSamples <= 4096},
		bound{"sample_freshness_seconds", within(adaptive.SampleFreshnessSeconds, 1, 86_400)},
		bound{"ewma_alpha_permille", within(adaptive.EWMAAlphaPermille, 1, 1000)},
		bound{"mad_multiplier_milli", within(adaptive.MADMultiplierMilli, 1000, 10_000)},
		bound{"min_rate_per_second", adaptive.MinRatePerSecond >= 1},
		bound{"max_rate_per_second", adaptive.MaxRatePerSecond >= adaptive.MinRatePerSecond && adaptive.MaxRatePerSecond <= 1_000_000},
		bound{"min_burst", adaptive.MinBurst >= 1},
		bound{"max_burst", adaptive.MaxBurst >= adaptive.MinBurst && adaptive.MaxBurst <= 1_000_000},
		bound{"max_step_permille", within(adaptive.MaxStepPermille, 1, 1000)},
		bound{"hysteresis_permille", within(adaptive.HysteresisPermille, 0, adaptive.MaxStepPermille)},
		bound{"cooldown_seconds", within(adaptive.CooldownSeconds, 0, 86_400)},
		bound{"max_groups", within(adaptive.MaxGroups, 1, 100_000)})
}

func normalizeCondition(condition *Condition) error {
	rawKey := condition.Key
	condition.Field = strings.TrimSpace(condition.Field)
	condition.Operator = strings.TrimSpace(condition.Operator)
	condition.Key = strings.ToLower(strings.TrimSpace(condition.Key))
	maximum := 64
	if condition.Field == "client_ip" && (condition.Operator == "ip_in_cidr" || condition.Operator == "ip_not_in_cidr") {
		// Stored conditions hold expanded ranges.
		maximum = maxIPConditionValues
	}
	switch {
	case len(conditionFieldOperators[condition.Field]) == 0:
		return refuse("field", fielderr.Invalid)
	case !validFieldOperator(condition.Field, condition.Operator):
		return refuse("operator", fielderr.Invalid)
	case len(condition.Values) < 1:
		return refuse("values", fielderr.Required)
	case len(condition.Values) > maximum:
		return refuse("values", fielderr.OutOfRange)
	}
	switch {
	case condition.Field == "header":
		if !headerNamePattern.MatchString(condition.Key) {
			return refuse("key", fielderr.InvalidFormat)
		}
	case slices.Contains(wafKeyedFields, condition.Field):
		// Names are case sensitive (form fields, JSON keys, cookies).
		condition.Key = strings.TrimSpace(rawKey)
		if condition.Key != "" && !wafNameKeyPattern.MatchString(condition.Key) {
			return refuse("key", fielderr.InvalidFormat)
		}
	case condition.Key != "":
		return refuse("key", fielderr.Invalid)
	}
	if err := normalizeConditionFilters(condition); err != nil {
		return err
	}
	if condition.Field == "client_ip" && (condition.Operator == "ip_in_cidr" || condition.Operator == "ip_not_in_cidr") {
		return normalizeIPNetworkCondition(condition)
	}
	seen := make(map[string]struct{}, len(condition.Values))
	for index := range condition.Values {
		value, err := normalizeConditionValue(condition.Field, condition.Operator, condition.Values[index])
		if err != nil {
			return err
		}
		if _, duplicate := seen[value]; duplicate {
			return refuse("values", fielderr.Duplicate)
		}
		seen[value] = struct{}{}
		condition.Values[index] = value
	}
	if (strings.HasPrefix(condition.Operator, "number_") || condition.Field == "ip_list") && len(condition.Values) != 1 {
		return refuse("values", fielderr.Invalid)
	}
	sort.Strings(condition.Values)
	return nil
}

// normalizeIPNetworkCondition expands every value of a client_ip CIDR
// condition (ParseIPNetworks) into sorted distinct CIDRs; two values covering
// the same CIDR are refused like any duplicate value.
func normalizeIPNetworkCondition(condition *Condition) error {
	seen := make(map[string]struct{}, len(condition.Values))
	values := make([]string, 0, len(condition.Values))
	for _, raw := range condition.Values {
		if strings.TrimSpace(raw) == "" {
			return refuse("values", fielderr.Required)
		}
		if utf8.RuneCountInString(raw) > 256 {
			return refuse("values", fielderr.TooLong)
		}
		prefixes, err := ParseIPNetworks(raw)
		if err != nil {
			return refuse("values", fielderr.InvalidFormat)
		}
		for _, prefix := range prefixes {
			value := prefix.String()
			if _, duplicate := seen[value]; duplicate {
				return refuse("values", fielderr.Duplicate)
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
		if len(values) > maxIPConditionValues {
			return refuse("values", fielderr.OutOfRange)
		}
	}
	sort.Strings(values)
	condition.Values = values
	return nil
}

func normalizeConditionValue(field, operator, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	switch {
	case value == "":
		return "", refuse("values", fielderr.Required)
	case !utf8.ValidString(value):
		return "", refuse("values", fielderr.InvalidFormat)
	case utf8.RuneCountInString(value) > 256:
		return "", refuse("values", fielderr.TooLong)
	}
	switch field {
	case "client_ip":
		address, err := netip.ParseAddr(value)
		if err != nil {
			return "", refuse("values", fielderr.InvalidFormat)
		}
		return address.String(), nil
	case "method":
		value = strings.ToUpper(value)
		if len(value) > 16 || strings.IndexFunc(value, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0 {
			return "", refuse("values", fielderr.InvalidFormat)
		}
	case "host":
		value = strings.ToLower(value)
	case "country":
		value = strings.ToUpper(value)
		if len(value) != 2 || value[0] < 'A' || value[0] > 'Z' || value[1] < 'A' || value[1] > 'Z' {
			return "", refuse("values", fielderr.InvalidFormat)
		}
	case "port":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			return "", refuse("values", fielderr.InvalidFormat)
		}
		value = strconv.FormatUint(port, 10)
	case "asn":
		asn, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return "", refuse("values", fielderr.InvalidFormat)
		}
		value = strconv.FormatUint(asn, 10)
	case "carrier", "ip_tag":
		// Tag names of the IP intelligence library: carrier:* / idc:*.
		value = strings.ToLower(value)
		prefix := "carrier:"
		if field == "ip_tag" {
			prefix = "idc:"
		}
		if _, ok := edgeconfig.IPIntelTagBit(value); !ok || !strings.HasPrefix(value, prefix) {
			return "", refuse("values", fielderr.InvalidFormat)
		}
	case "province", "city":
		// GB/T 2260 six digit codes (province xx0000).
		target := edgeconfig.WAFIPIntelProvince
		if field == "city" {
			target = edgeconfig.WAFIPIntelCity
		}
		if !edgeconfig.ValidIPIntelValue(target, value) {
			return "", refuse("values", fielderr.InvalidFormat)
		}
	case "http_version":
		if value != "1.0" && value != "1.1" && value != "2" && value != "3" {
			return "", refuse("values", fielderr.InvalidFormat)
		}
	case "ip_list":
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil {
			return "", refuse("values", fielderr.InvalidFormat)
		}
		value = id.String()
	case "distinct_user_agents", "status_404_count":
		count, err := strconv.ParseUint(value, 10, 32)
		if err != nil || count < 1 || count > 1024 {
			return "", refuse("values", fielderr.InvalidFormat)
		}
		value = strconv.FormatUint(count, 10)
	case "ja4":
		// Whole fingerprints are exactly what the node computes
		// (edgeconfig.JA4Pattern); a rule on any other text could never match.
		if operator == "prefix" && !ja4PrefixPattern.MatchString(value) ||
			operator != "prefix" && !edgeconfig.ValidJA4(value) {
			return "", refuse("values", fielderr.InvalidFormat)
		}
	}
	switch operator {
	case "regex", "not_regex":
		if _, err := regexp.Compile(value); err != nil {
			return "", refuse("values", fielderr.InvalidFormat)
		}
	case "number_gt", "number_lt", "number_neq", "number_gte", "number_lte", "number_eq":
		if field != "port" && field != "asn" && !slices.Contains(wafNumberFields, field) &&
			!slices.Contains(wafContentFieldNames, field) {
			break
		}
		number, err := strconv.ParseUint(value, 10, 40)
		if err != nil {
			return "", refuse("values", fielderr.InvalidFormat)
		}
		value = strconv.FormatUint(number, 10)
	case "detect":
		if !slices.Contains(edgeconfig.WAFInspectDetectors(), value) {
			return "", refuse("values", fielderr.InvalidFormat)
		}
	}
	return value, nil
}

func validFieldOperator(field, operator string) bool {
	return slices.Contains(conditionFieldOperators[field], operator)
}

// conditionFieldOperators are the operators each condition field takes.
var conditionFieldOperators = map[string][]string{
	"client_ip":            {"equals", "not_equals", "ip_in_cidr", "ip_not_in_cidr"},
	"ip_list":              ipListOperators,
	"host":                 {"equals", "not_equals", "prefix", "suffix", "contains", "in", "not_in"},
	"path":                 append([]string{"in", "not_in"}, wafContentOperators...),
	"method":               {"equals", "not_equals", "in", "not_in"},
	"header":               append([]string{"in", "not_in"}, wafContentOperators...),
	"args":                 wafContentOperators,
	"query":                wafContentOperators,
	"body":                 wafContentOperators,
	"request_uri":          wafContentOperators,
	"cookie":               wafContentOperators,
	"user_agent":           wafContentOperators,
	"referer":              wafContentOperators,
	"upload_filename":      wafContentOperators,
	"upload_extension":     wafContentOperators,
	"header_names":         wafContentOperators,
	"content_type":         wafContentOperators,
	"http_version":         wafHTTPVersionOperators,
	"request_length":       wafLengthOperators,
	"body_length":          wafLengthOperators,
	"uri_length":           wafLengthOperators,
	"header_max_length":    wafLengthOperators,
	"header_count":         wafLengthOperators,
	"arg_count":            wafLengthOperators,
	"country":              {"equals", "not_equals", "in", "not_in"},
	"asn":                  {"number_eq", "number_gte", "number_lte", "equals", "not_equals", "in", "not_in"},
	"carrier":              {"equals", "not_equals", "in", "not_in"},
	"ip_tag":               {"equals", "not_equals", "in", "not_in"},
	"province":             {"equals", "not_equals", "in", "not_in"},
	"city":                 {"equals", "not_equals", "in", "not_in"},
	"ja4":                  {"equals", "not_equals", "prefix", "in", "not_in"},
	"port":                 {"number_eq", "number_gte", "number_lte", "in", "not_in"},
	"distinct_user_agents": {"number_gte"},
	"status_404_count":     {"number_gte"},

	"multipart_field_names":      wafContentOperators,
	"multipart_part_count":       wafLengthOperators,
	"multipart_field_max_length": wafLengthOperators,
}

// WAF content operators (edgeconfig.WAFInspect): text comparisons on a
// request value, detect, and number_* on a value whose last filter is length.
var (
	wafContentOperators = []string{"equals", "not_equals", "prefix", "suffix", "contains", "not_contains", "contains_all",
		"regex", "not_regex", "detect", "number_gt", "number_gte", "number_lt", "number_lte", "number_eq", "number_neq"}
	wafLengthOperators = []string{"number_gt", "number_gte", "number_lt", "number_lte", "number_eq", "number_neq"}
	// ip_list: the client address is (in_ip_list) or is not (not_in_ip_list)
	// in the named IP list; one list ID per condition.
	ipListOperators = []string{"in_ip_list", "not_in_ip_list"}
	// http_version: the request's HTTP version is one of (equals) or none of
	// (not_equals) the values 1.0, 1.1, 2, 3.
	wafHTTPVersionOperators = []string{"equals", "not_equals"}
	// wafKeyedFields may name one value: header (required), args / query /
	// body (form field or JSON key path a.b.0) / cookie (optional).
	wafKeyedFields    = []string{"args", "query", "body", "cookie"}
	wafNameKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]{1,128}$`)
	wafFilters        = []string{"lowercase", "base64_decode", "unicode_decode", "html_unescape", "length"}
	wafNumberFields   = []string{"request_length", "body_length", "uri_length", "header_max_length", "header_count", "arg_count",
		"multipart_part_count", "multipart_field_max_length"}
	wafBodyFields = []string{"args", "body", "upload_filename", "upload_extension", "body_length", "request_length",
		"multipart_field_names", "multipart_part_count", "multipart_field_max_length"}
)

func isSEC11CountField(field string) bool {
	return field == "distinct_user_agents" || field == "status_404_count"
}

func validKind(value string) bool {
	return value == KindWAF || value == KindCC || value == KindACL
}
func validDecision(value string) bool { return value == ActionAllow || value == ActionBlock }
func validAction(value string) bool {
	return slices.Contains([]string{ActionAllow, ActionBlock, ActionRateLimit, ActionChallenge, ActionLog, ActionManagedWAF, ActionBan}, value)
}

func sortRules(rules []Rule) {
	sort.SliceStable(rules, func(left, right int) bool {
		if rules[left].Priority != rules[right].Priority {
			return rules[left].Priority < rules[right].Priority
		}
		return rules[left].ID.String() < rules[right].ID.String()
	})
}

func validWriteMetadata(key, requestID string) bool {
	return idempotencyPattern.MatchString(key) && strings.TrimSpace(requestID) != ""
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func redact(policy *Policy, actor Actor) {
	if metadata, protected := licensedWAFMetadata(*policy); protected {
		policy.Name = metadata.Name
		policy.Description = metadata.Description
		policy.Rules = nil
		policy.Origin = "system"
		policy.Protected = true
		policy.LibraryID = metadata.LibraryID
	} else {
		policy.Origin = "custom"
		policy.Protected = false
		policy.LibraryID = ""
	}
	if actor.ScopeKind == "tenant" {
		policy.Owner = nil
	}
}

// IPListReferences are the IP list IDs the rules' ip_list conditions name, in
// order of first appearance.
func IPListReferences(rules []Rule) []uuid.UUID {
	var ids []uuid.UUID
	for _, rule := range rules {
		for _, condition := range rule.Conditions {
			if condition.Field != "ip_list" || len(condition.Values) != 1 {
				continue
			}
			if id, err := uuid.Parse(condition.Values[0]); err == nil && !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	return ids
}
