package errorpagecontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/themepack"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	ProductionSnapshotSchema    = "cdnca.edge.error-page-snapshot/v1"
	ProductionSnapshotMediaType = "application/vnd.cdnca.edge-error-page-snapshot+json;version=1"
)

type ProductionSnapshotBinding struct {
	TenantID             string `json:"tenant_id"`
	ConfigurationScopeID string `json:"configuration_scope_id"`
	PublicationRevision  uint64 `json:"publication_revision"`
}

type ProductionSnapshotResource struct {
	MIMEType string `json:"mime_type"`
	Size     int64  `json:"size_bytes"`
	SHA256   string `json:"sha256"`
	Body     []byte `json:"body"`
}

type ProductionSnapshotRule struct {
	ID       string                     `json:"id"`
	Category string                     `json:"category"`
	Match    SnapshotMatch              `json:"match"`
	Resource ProductionSnapshotResource `json:"resource"`
}

type ProductionSnapshotScope struct {
	Rules []ProductionSnapshotRule `json:"rules"`
}

type ProductionSnapshotSite struct {
	SiteKey string                   `json:"site_key"`
	Rules   []ProductionSnapshotRule `json:"rules"`
}

type ProductionSnapshotDocument struct {
	Schema  string                    `json:"schema"`
	Binding ProductionSnapshotBinding `json:"binding"`
	Global  ProductionSnapshotScope   `json:"global"`
	Sites   []ProductionSnapshotSite  `json:"sites"`
	// Slots are the node pages of the platform's error page slots
	// (errpage-3, ERROR_PAGE_SLOTS): the slots a node answers itself and the
	// region / node overrides, ordered by (key, node, region). Omitted when
	// none, so a snapshot without them keeps its bytes for earlier agents.
	Slots []ProductionSnapshotSlot `json:"slots,omitempty"`
}

// ProductionSnapshotSlot is one slot node page: Category / Status are the
// node page's (siteobject node page categories), Region / NodeID its
// selector (both empty: every node).
type ProductionSnapshotSlot struct {
	Key      string                     `json:"key"`
	Category string                     `json:"category"`
	Status   int                        `json:"status"`
	Region   string                     `json:"region,omitempty"`
	NodeID   string                     `json:"node_id,omitempty"`
	Resource ProductionSnapshotResource `json:"resource"`
}

type ProductionSnapshotRequest struct {
	TenantID uuid.UUID
	ScopeID  uuid.UUID
}

type ProductionSnapshotArtifact struct {
	ProductionBundleArtifact
	Binding          ProductionSnapshotBinding
	SigningPublicKey ed25519.PublicKey
	// HasSlots: the snapshot carries slot node pages (its rollout needs
	// CAPABILITY_NAME_ERROR_PAGE_SLOTS: earlier agents refuse the field).
	HasSlots bool
}

type ProductionSnapshotCompiler struct {
	store  ContentStore
	signer ProductionBundleSigner
}

type productionSnapshotSource struct {
	TenantID, ScopeID, PlatformScopeID uuid.UUID
	SiteIDs                            map[string]struct{}
	Policy                             Snapshot
	ThemePages                         []ThemeDefaultPage
}

// ThemeDefaultPage is a node default error page rendered by the theme the
// publication pins (theme_error_pages, ADR 0007 §7.3).
type ThemeDefaultPage struct {
	Category string
	Status   int
	Body     []byte
}

func NewProductionSnapshotCompiler(store ContentStore, signer ProductionBundleSigner) (*ProductionSnapshotCompiler, error) {
	if store == nil || signer == nil || !store.Capabilities().runtimeReady() ||
		!productionBundleIdentifier.MatchString(signer.SigningKeyID()) || len(signer.SigningPublicKey()) != ed25519.PublicKeySize {
		return nil, ErrInvalidStore
	}
	return &ProductionSnapshotCompiler{store: store, signer: signer}, nil
}

func (compiler *ProductionSnapshotCompiler) Build(ctx context.Context, tx pgx.Tx, request ProductionSnapshotRequest) (ProductionSnapshotArtifact, error) {
	if compiler == nil || ctx == nil || tx == nil || request.TenantID == uuid.Nil || request.ScopeID == uuid.Nil {
		return ProductionSnapshotArtifact{}, ErrInvalidInput
	}
	source, err := loadProductionSnapshotSource(ctx, tx, request)
	if err != nil {
		return ProductionSnapshotArtifact{}, err
	}
	return compiler.buildSelected(ctx, source)
}

func loadProductionSnapshotSource(ctx context.Context, tx pgx.Tx, request ProductionSnapshotRequest) (productionSnapshotSource, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('error-page-publication',0))`); err != nil {
		return productionSnapshotSource{}, fmt.Errorf("lock production error page snapshot: %w", err)
	}
	source := productionSnapshotSource{TenantID: request.TenantID, ScopeID: request.ScopeID, SiteIDs: make(map[string]struct{})}
	var persistedTenant *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1 AND kind='tenant' FOR SHARE`, request.ScopeID).Scan(&persistedTenant); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return productionSnapshotSource{}, ErrNotFound
		}
		return productionSnapshotSource{}, err
	}
	if persistedTenant == nil || *persistedTenant != request.TenantID {
		return productionSnapshotSource{}, ErrConflict
	}
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL FOR SHARE`).Scan(&source.PlatformScopeID); err != nil {
		return productionSnapshotSource{}, err
	}
	var canonical, persistedDigest []byte
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision,canonical_snapshot,snapshot_sha256 FROM error_page_publications ORDER BY revision DESC LIMIT 1`).
		Scan(&revision, &canonical, &persistedDigest); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return productionSnapshotSource{}, ErrNotFound
		}
		return productionSnapshotSource{}, err
	}
	actual := sha256.Sum256(canonical)
	if revision < 1 || len(persistedDigest) != sha256.Size || !bytes.Equal(actual[:], persistedDigest) ||
		edgeconfig.RejectDuplicateJSONKeys(canonical) != nil {
		return productionSnapshotSource{}, ErrConflict
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source.Policy); err != nil {
		return productionSnapshotSource{}, ErrConflict
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return productionSnapshotSource{}, ErrConflict
	}
	reencoded, err := json.Marshal(source.Policy)
	if err != nil || !bytes.Equal(reencoded, canonical) || source.Policy.Schema != SchemaV1 || source.Policy.Revision != revision ||
		!productionBundleIdentifier.MatchString(source.Policy.Version) {
		return productionSnapshotSource{}, ErrConflict
	}
	// The platform theme the publication pins (no tenant themes in the
	// community edition).
	themePackage := source.Policy.ThemePackageSHA256
	if themePackage != "" {
		if source.ThemePages, err = loadThemeDefaultPages(ctx, tx, themePackage); err != nil {
			return productionSnapshotSource{}, err
		}
	} else {
		source.ThemePages = BuiltinBlockPages()
	}
	rows, err := tx.Query(ctx, `SELECT id FROM sites WHERE scope_id=$1 AND deleted_at IS NULL ORDER BY id FOR SHARE`, request.ScopeID)
	if err != nil {
		return productionSnapshotSource{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var siteID uuid.UUID
		if err := rows.Scan(&siteID); err != nil {
			return productionSnapshotSource{}, err
		}
		source.SiteIDs[siteID.String()] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return productionSnapshotSource{}, err
	}
	return source, nil
}

func (compiler *ProductionSnapshotCompiler) buildSelected(ctx context.Context, source productionSnapshotSource) (ProductionSnapshotArtifact, error) {
	if compiler == nil || ctx == nil || source.TenantID == uuid.Nil || source.ScopeID == uuid.Nil || source.PlatformScopeID == uuid.Nil ||
		source.Policy.Schema != SchemaV1 || source.Policy.Revision < 1 || !productionBundleIdentifier.MatchString(source.Policy.Version) {
		return ProductionSnapshotArtifact{}, ErrInvalidInput
	}
	document := ProductionSnapshotDocument{
		Schema:  ProductionSnapshotSchema,
		Binding: ProductionSnapshotBinding{TenantID: source.TenantID.String(), ConfigurationScopeID: source.ScopeID.String(), PublicationRevision: uint64(source.Policy.Revision)},
		Global:  ProductionSnapshotScope{Rules: []ProductionSnapshotRule{}}, Sites: []ProductionSnapshotSite{},
	}
	cache := make(map[string]ProductionSnapshotResource)
	for _, rule := range source.Policy.Global.Rules {
		materialized, err := compiler.materializeRule(ctx, rule, source.PlatformScopeID, nil, cache)
		if err != nil {
			return ProductionSnapshotArtifact{}, err
		}
		document.Global.Rules = append(document.Global.Rules, materialized)
	}
	themeRules, err := themeDefaultRules(source.Policy.Global.Rules, source.ThemePages)
	if err != nil {
		return ProductionSnapshotArtifact{}, err
	}
	if themeRules, err = compiler.applySlots(ctx, source, themeRules, cache); err != nil {
		return ProductionSnapshotArtifact{}, err
	}
	document.Global.Rules = append(document.Global.Rules, themeRules...)
	if len(document.Global.Rules) > MaxEdgeRulesPerScope {
		return ProductionSnapshotArtifact{}, ErrQuotaExceeded
	}
	if document.Slots, err = compiler.nodeSlotPages(ctx, source, cache); err != nil {
		return ProductionSnapshotArtifact{}, err
	}
	for _, site := range source.Policy.Sites {
		if _, selected := source.SiteIDs[site.SiteKey]; !selected {
			continue
		}
		if _, err := uuid.Parse(site.SiteKey); err != nil {
			return ProductionSnapshotArtifact{}, ErrConflict
		}
		materializedSite := ProductionSnapshotSite{SiteKey: site.SiteKey, Rules: []ProductionSnapshotRule{}}
		for _, rule := range site.Rules {
			materialized, err := compiler.materializeRule(ctx, rule, source.ScopeID, &source.TenantID, cache)
			if err != nil {
				return ProductionSnapshotArtifact{}, err
			}
			materializedSite.Rules = append(materializedSite.Rules, materialized)
		}
		document.Sites = append(document.Sites, materializedSite)
	}
	sort.Slice(document.Sites, func(left, right int) bool { return document.Sites[left].SiteKey < document.Sites[right].SiteKey })
	wire, err := json.Marshal(document)
	if err != nil || len(wire) == 0 || int64(len(wire)) > MaxEdgePolicyBytes {
		return ProductionSnapshotArtifact{}, ErrQuotaExceeded
	}
	signature, err := compiler.signer.Sign(ctx, wire)
	publicKey := append(ed25519.PublicKey(nil), compiler.signer.SigningPublicKey()...)
	if err != nil || len(signature) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(publicKey, wire, signature) {
		return ProductionSnapshotArtifact{}, ErrUnavailable
	}
	digest := sha256.Sum256(wire)
	return ProductionSnapshotArtifact{
		ProductionBundleArtifact: ProductionBundleArtifact{WireBytes: bytes.Clone(wire), SHA256: hex.EncodeToString(digest[:]),
			Signature: bytes.Clone(signature), SigningKeyID: compiler.signer.SigningKeyID(), MediaType: ProductionSnapshotMediaType},
		Binding: document.Binding, SigningPublicKey: publicKey, HasSlots: len(document.Slots) > 0,
	}, nil
}

func (compiler *ProductionSnapshotCompiler) materializeRule(
	ctx context.Context,
	rule SnapshotRule,
	scopeID uuid.UUID,
	tenantID *uuid.UUID,
	cache map[string]ProductionSnapshotResource,
) (ProductionSnapshotRule, error) {
	if !productionBundleIdentifier.MatchString(rule.ID) || !validCategory(rule.Category) ||
		!validProductionBundleMatch(rule.Category, rule.Match) || rule.Resource.File != "sha256/"+rule.Resource.SHA256 ||
		rule.Resource.Size < 1 || rule.Resource.Size > MaxEdgeResourceBytes || !validDigestString(rule.Resource.SHA256) {
		return ProductionSnapshotRule{}, ErrConflict
	}
	cacheKey := scopeID.String() + "/" + rule.Resource.SHA256
	resource, found := cache[cacheKey]
	if !found {
		ref := ObjectRef{TenantID: tenantID, ScopeID: scopeID, LogicalKey: "error-pages/objects/" + scopeID.String() + "/" + rule.Resource.SHA256}
		info, err := compiler.store.Stat(ctx, ref)
		if err != nil {
			return ProductionSnapshotRule{}, wrapUnavailable("stat production error page snapshot object", err)
		}
		if info.Size != rule.Resource.Size || info.SHA256 != rule.Resource.SHA256 || info.MIMEType != rule.Resource.MIMEType ||
			info.ImmutableToken != "sha256:"+rule.Resource.SHA256 {
			return ProductionSnapshotRule{}, ErrConflict
		}
		reader, err := compiler.store.Open(ctx, ref, info.ImmutableToken)
		if err != nil {
			return ProductionSnapshotRule{}, wrapUnavailable("open production error page snapshot object", err)
		}
		body, err := readProductionBundleBody(reader, info.Size)
		if err != nil {
			return ProductionSnapshotRule{}, err
		}
		if digestBytes(body) != rule.Resource.SHA256 || validateStaticBody(rule.Resource.MIMEType, body) != nil {
			return ProductionSnapshotRule{}, ErrUnsafeContent
		}
		resource = ProductionSnapshotResource{MIMEType: info.MIMEType, Size: info.Size, SHA256: info.SHA256, Body: body}
		cache[cacheKey] = resource
	}
	resource.Body = bytes.Clone(resource.Body)
	return ProductionSnapshotRule{ID: rule.ID, Category: rule.Category, Match: rule.Match, Resource: resource}, nil
}

func loadThemeDefaultPages(ctx context.Context, tx pgx.Tx, packageSHA256 string) ([]ThemeDefaultPage, error) {
	digest, err := hex.DecodeString(packageSHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != packageSHA256 {
		return nil, ErrConflict
	}
	rows, err := tx.Query(ctx, `SELECT category,status_code,body FROM theme_error_pages
		WHERE package_sha256=$1 ORDER BY category,status_code`, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pages []ThemeDefaultPage
	for rows.Next() {
		var page ThemeDefaultPage
		if err := rows.Scan(&page.Category, &page.Status, &page.Body); err != nil {
			return nil, err
		}
		pages = append(pages, page)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(pages) == 0 {
		// The publication names a package the database no longer explains.
		return nil, ErrConflict
	}
	if hasBlockPages(pages) {
		return pages, nil
	}
	// A package stored before migration 471 has no block pages (edge_route
	// 403/429, sec-followup P13): render them from the package itself, so a
	// node block page keeps the pinned theme's brand.
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT package_body FROM theme_packages WHERE package_sha256=$1`, digest).Scan(&raw); err != nil {
		return nil, err
	}
	return completeBlockPages(pages, raw), nil
}

// BuiltinBlockPages are the built-in theme's block pages (edge_route
// 403/429): what a node answers a refused request with while no theme is
// activated (sec-followup P13; 73 had no theme package at all). The other
// node pages keep their state without a theme (no theme, no page).
func BuiltinBlockPages() []ThemeDefaultPage {
	return completeBlockPages(nil, nil)
}

// BuiltinBlockSnapshot is the error page document of a scope that never
// published error pages (no error_page_publications row, so no snapshot
// artifact): the built-in block pages as global rules, no site rules.
func BuiltinBlockSnapshot() (ProductionSnapshotDocument, error) {
	rules, err := themeDefaultRules(nil, BuiltinBlockPages())
	if err != nil {
		return ProductionSnapshotDocument{}, err
	}
	return ProductionSnapshotDocument{Schema: ProductionSnapshotSchema, Global: ProductionSnapshotScope{Rules: rules},
		Sites: []ProductionSnapshotSite{}}, nil
}

func hasBlockPages(pages []ThemeDefaultPage) bool {
	for _, page := range pages {
		if page.Category == CategoryEdgeRoute {
			return true
		}
	}
	return false
}

// completeBlockPages adds the edge_route pages raw (a theme package) renders
// to pages; a package that no longer renders adds the built-in theme's.
func completeBlockPages(pages []ThemeDefaultPage, raw []byte) []ThemeDefaultPage {
	rendered := themepack.DefaultRendered()
	if raw != nil {
		if own, err := themepack.Render(raw); err == nil {
			rendered = own
		}
	}
	result := slices.Clone(pages)
	for _, page := range rendered.ErrorPages {
		if page.Category == CategoryEdgeRoute {
			result = append(result, ThemeDefaultPage{Category: page.Category, Status: page.Status, Body: bytes.Clone(page.Body)})
		}
	}
	slices.SortFunc(result, func(left, right ThemeDefaultPage) int {
		if left.Category != right.Category {
			return strings.Compare(left.Category, right.Category)
		}
		return left.Status - right.Status
	})
	return result
}

// themeDefaultRules turns the pinned theme's pages into global rules for the
// categories that no platform global rule covers; a category the platform has
// configured keeps exactly its own pages (no mixed precedence).
func themeDefaultRules(global []SnapshotRule, pages []ThemeDefaultPage) ([]ProductionSnapshotRule, error) {
	covered := make(map[string]struct{}, len(global))
	for _, rule := range global {
		covered[rule.Category] = struct{}{}
	}
	rules := make([]ProductionSnapshotRule, 0, len(pages))
	for _, page := range pages {
		if _, ok := covered[page.Category]; ok {
			continue
		}
		match := SnapshotMatch{Codes: []int{page.Status}}
		if !validCategory(page.Category) || !validProductionBundleMatch(page.Category, match) ||
			ValidateThemedHTML(page.Body) != nil {
			return nil, ErrUnsafeContent
		}
		rules = append(rules, ProductionSnapshotRule{
			ID: "theme." + page.Category + "." + strconv.Itoa(page.Status), Category: page.Category, Match: match,
			Resource: ProductionSnapshotResource{MIMEType: "text/html", Size: int64(len(page.Body)),
				SHA256: digestBytes(page.Body), Body: bytes.Clone(page.Body)},
		})
	}
	return rules, nil
}

// applySlots puts the platform's bound slots (Policy.Slots) in place of the
// theme default page each replaces, keeping the theme rule ID (the node treats
// theme.edge_route.* as its own block pages only). A slot whose category a
// platform global rule covers stays out, like the theme page.
func (compiler *ProductionSnapshotCompiler) applySlots(ctx context.Context, source productionSnapshotSource,
	rules []ProductionSnapshotRule, cache map[string]ProductionSnapshotResource) ([]ProductionSnapshotRule, error) {
	covered := make(map[string]struct{}, len(source.Policy.Global.Rules))
	for _, rule := range source.Policy.Global.Rules {
		covered[rule.Category] = struct{}{}
	}
	for _, slot := range source.Policy.Slots {
		if _, ok := covered[slot.Category]; ok || !replacesThemePage(slot) {
			continue
		}
		materialized, err := compiler.materializeRule(ctx, SnapshotRule{
			ID: "theme." + slot.Category + "." + strconv.Itoa(slot.Status), Category: slot.Category,
			Match: SnapshotMatch{Codes: []int{slot.Status}}, Resource: slot.Resource,
		}, source.PlatformScopeID, nil, cache)
		if err != nil {
			return nil, err
		}
		replaced := false
		for index := range rules {
			if rules[index].ID == materialized.ID {
				rules[index], replaced = materialized, true
			}
		}
		if !replaced {
			rules = append(rules, materialized)
		}
	}
	return rules, nil
}

// replacesThemePage: a global binding of a slot whose page is a theme
// default page (slotNodePages); everything else is a node page.
func replacesThemePage(slot SnapshotSlot) bool {
	_, theme := slotNodePages[slot.Key]
	return theme && slot.Region == "" && slot.NodeID == ""
}

// nodeSlotPages materializes the pinned slots that reach nodes as node pages
// (errpage-3). A tenant on its own theme (PA-26) keeps the slots too: they
// are the platform's own responses, not theme pages.
func (compiler *ProductionSnapshotCompiler) nodeSlotPages(ctx context.Context, source productionSnapshotSource,
	cache map[string]ProductionSnapshotResource) ([]ProductionSnapshotSlot, error) {
	var slots []ProductionSnapshotSlot
	for _, slot := range source.Policy.Slots {
		if replacesThemePage(slot) {
			continue
		}
		// errpage-ovr: a region / node override of http_502/504 replaces the
		// theme's edge_connect page on those nodes.
		materialized, err := compiler.materializeRule(ctx, SnapshotRule{
			ID: "slot." + slot.Key, Category: CategoryEdgeRoute, Match: SnapshotMatch{Codes: []int{403}}, Resource: slot.Resource,
		}, source.PlatformScopeID, nil, cache)
		if err != nil {
			return nil, err
		}
		slots = append(slots, ProductionSnapshotSlot{Key: slot.Key, Category: slot.Category, Status: slot.Status,
			Region: slot.Region, NodeID: slot.NodeID, Resource: materialized.Resource})
	}
	return slots, nil
}

func validDigestString(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == hex.EncodeToString(decoded)
}
