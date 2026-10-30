package edgepublish

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func siteRuntimeSecurityFragments(document siteRuntimeV2Document) (edgeconfig.SecurityFragments, error) {
	return edgeconfig.RenderSecurityFragments(document.ConfigurationScopeID, document.ConfigVersionID, siteRuntimeSecurityListeners(document))
}

func siteRuntimeSecurityListeners(document siteRuntimeV2Document) []edgeconfig.SecurityListener {
	var listeners []edgeconfig.SecurityListener
	for _, site := range document.Sites {
		for _, listener := range site.Listeners {
			protocol := edgeconfig.ProtocolHTTP
			if listener.TLS != nil {
				protocol = edgeconfig.ProtocolHTTPS
			}
			value := edgeconfig.SecurityListener{SiteID: site.ID, Domain: site.Domains[0], Port: uint16(listener.Port), Protocol: protocol}
			if listener.Security != nil {
				value.Security = *listener.Security
			}
			listeners = append(listeners, value)
		}
	}
	return listeners
}

// siteRuntimeV2ListenerSecurity is one listener's security exactly as the
// legacy renderer compiles the site for that port (compileSiteFact): the
// bound policies and CC, the managed WAF of the WAF policy and the site's JS
// challenge (tenantID: the challenge rule's tenants.id). nil without any.
func siteRuntimeV2ListenerSecurity(scopeID, tenantID uuid.UUID, fact siteFact, port uint16, bindings []securityBindingFact) (*edgeconfig.ListenerSecurity, error) {
	if len(bindings) == 0 && fact.challenge == nil {
		return nil, nil
	}
	// The v2 server serves every live domain (server_name): its rules are
	// not pinned to the primary like the legacy renderer's single-domain
	// server (compileSecurityRuleMatchesFor), and a CC host condition may
	// name any of them.
	domains := siteRuntimeV2Domains(fact)
	_, compiled, err := compileSiteFact(scopeID, fact, port, nil, bindings, domains)
	if err != nil {
		return nil, err
	}
	policies, err := compileSecurityPoliciesFor(fact, domains, port, bindings)
	if err != nil {
		return nil, err
	}
	security := &edgeconfig.ListenerSecurity{Policies: policies, CC: compiled.CCV2}
	if compiled.ManagedWAF != nil {
		security.ManagedWAF, err = edgeconfig.CanonicalListenerManagedWAF(*compiled.ManagedWAF)
		if err != nil {
			return nil, ErrUnsupportedSecurityPolicy
		}
	}
	if compiled.Challenge != nil {
		if tenantID == uuid.Nil {
			return nil, ErrInvalidInput
		}
		security.Challenge = &edgeconfig.ListenerChallenge{TenantID: tenantID.String(),
			PolicyID: compiled.Challenge.PolicyID, PolicyVersion: compiled.Challenge.PolicyVersion}
	}
	return security, nil
}

// loadSiteRuntimeV2CRSFiles is the signed release's CRS files for the
// document's managed WAF: the CRS rule text it loads (from the synced system
// rule catalog) and the bytes of each CRS profile pack it selects (from the
// downloaded local artifacts); none without a managed WAF.
func loadSiteRuntimeV2CRSFiles(ctx context.Context, tx pgx.Tx, canonical []byte) (map[string][]byte, error) {
	var document siteRuntimeV2Document
	if err := json.Unmarshal(canonical, &document); err != nil {
		return nil, ErrInvalidInput
	}
	refs, err := edgeconfig.ListenerCRSProfiles(siteRuntimeSecurityListeners(document))
	if err != nil {
		return nil, ErrInvalidInput
	}
	if len(refs) == 0 {
		return nil, nil
	}
	crs, err := loadCRSInputs(ctx, tx)
	if err != nil {
		return nil, err
	}
	return siteRuntimeV2CRSFiles(canonical, crs.RuleText, crs.Profiles, crs.Apps)
}

// siteRuntimeV2CRSFiles is the release files of the CRS rule text and CRS
// profile packs the document's managed WAF loads.
func siteRuntimeV2CRSFiles(canonical []byte, rules *edgeconfig.CRSRuleText, profiles securitypolicy.CRSProfiles,
	apps securitypolicy.CRSApps) (map[string][]byte, error) {
	var document siteRuntimeV2Document
	if err := json.Unmarshal(canonical, &document); err != nil {
		return nil, ErrInvalidInput
	}
	listeners := siteRuntimeSecurityListeners(document)
	refs, err := edgeconfig.ListenerCRSProfiles(listeners)
	if err != nil {
		return nil, ErrInvalidInput
	}
	byDigest := map[string]securitypolicy.CRSProfile{}
	for _, profile := range profiles {
		byDigest[profile.Profile.Ref.SHA256] = profile
	}
	selected := make([]edgeconfig.CRSProfile, 0, len(refs))
	packs := make(map[string][]byte, len(refs))
	for _, ref := range refs {
		profile, ok := byDigest[ref.SHA256]
		if !ok || profile.Profile.Ref != ref {
			return nil, ErrUnsupportedSecurityPolicy
		}
		selected = append(selected, profile.Profile)
		packs[edgeconfig.ListenerCRSProfilePath(ref.SHA256)] = profile.Content
	}
	appRefs, err := edgeconfig.ListenerCRSApps(listeners)
	if err != nil {
		return nil, ErrInvalidInput
	}
	appsByDigest := map[string]securitypolicy.CRSApp{}
	for _, app := range apps {
		appsByDigest[app.App.Ref.SHA256] = app
	}
	selectedApps := make([]edgeconfig.CRSApp, 0, len(appRefs))
	for _, ref := range appRefs {
		app, ok := appsByDigest[ref.SHA256]
		if !ok || app.App.Ref != ref {
			return nil, ErrUnsupportedSecurityPolicy
		}
		selectedApps = append(selectedApps, app.App)
		packs[edgeconfig.ListenerCRSAppPath(ref.SHA256)] = app.Content
	}
	files, err := edgeconfig.ListenerCRSReleaseFiles(listeners, rules, selected, selectedApps...)
	if err != nil {
		return nil, ErrUnsupportedSecurityPolicy
	}
	for path, content := range packs {
		files[path] = content
	}
	return files, nil
}

// validateSiteRuntimeV2CRSFiles requires exactly the CRS files the
// document's managed WAF loads: the rule text files (checked as the node
// checks them) and each selected profile pack (bytes with its digest that
// load as that profile).
func validateSiteRuntimeV2CRSFiles(canonical []byte, crs map[string][]byte) error {
	var document siteRuntimeV2Document
	if err := json.Unmarshal(canonical, &document); err != nil {
		if len(crs) == 0 {
			return nil // validated as a document elsewhere; nothing to carry
		}
		return ErrInvalidInput
	}
	refs, err := edgeconfig.ListenerCRSProfiles(siteRuntimeSecurityListeners(document))
	if err != nil {
		return ErrInvalidInput
	}
	if len(refs) == 0 {
		if len(crs) != 0 {
			return ErrInvalidInput
		}
		return nil
	}
	text := &edgeconfig.CRSRuleText{Files: map[string][]byte{}}
	profiles := securitypolicy.CRSProfiles{}
	apps := securitypolicy.CRSApps{}
	prefix := edgeconfig.ListenerCRSReleasePath("")
	for path, content := range crs {
		if digest, ok := edgeconfig.ListenerCRSAppDigest(path); ok {
			_, app, err := rulepack.LoadCRSApp(content, digest)
			if err != nil {
				return ErrInvalidInput
			}
			apps[app.Ref.PackID] = securitypolicy.CRSApp{App: app, Content: content}
			continue
		}
		if digest, ok := edgeconfig.ListenerCRSProfileDigest(path); ok {
			_, profile, err := rulepack.LoadCRSProfile(content, digest)
			if err != nil {
				return ErrInvalidInput
			}
			profiles[profile.Ref.PackID] = securitypolicy.CRSProfile{Profile: profile, Content: content}
			continue
		}
		if !strings.HasPrefix(path, prefix) {
			return ErrInvalidInput
		}
		text.Files[strings.TrimPrefix(path, prefix)] = content
	}
	expected, err := siteRuntimeV2CRSFiles(canonical, text, profiles, apps)
	if err != nil || len(expected) != len(crs) {
		return ErrInvalidInput
	}
	for path := range expected {
		if _, ok := crs[path]; !ok {
			return ErrInvalidInput
		}
	}
	return nil
}
