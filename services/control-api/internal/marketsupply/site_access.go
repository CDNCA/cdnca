package marketsupply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/siteconf"
	"github.com/cdnca/cdnca/services/control-api/internal/siteaccess"
	"github.com/google/uuid"
)

// SiteAccessSettings is the subset of siteaccess.Service the leaf drives.
type SiteAccessSettings interface {
	Get(ctx context.Context, actor siteaccess.Actor, siteID uuid.UUID) (siteaccess.State, error)
	Update(ctx context.Context, actor siteaccess.Actor, request siteaccess.UpdateRequest) (siteaccess.State, error)
}

// WithSiteAccess lets market sites carry their access settings (fix-mktsiteconf2).
func (s *Service) WithSiteAccess(settings SiteAccessSettings) *Service {
	s.access = settings
	return s
}

// siteAccessDocument is siteconf's site_access object: siteaccess.Settings
// with basic auth users as the subscriber's salted hashes (never a
// password, fix-mktsiteconf4).
type siteAccessDocument struct {
	siteaccess.Settings
	BasicAuth *struct {
		Realm               string                     `json:"realm"`
		Users               []edgeconfig.BasicAuthUser `json:"users"`
		ExcludePathPrefixes []string                   `json:"exclude_path_prefixes"`
	} `json:"basic_auth"`
}

// siteAccessWrite decodes siteconf's site_access object into the settings
// to write and the hashed basic auth users; absent is every setting off.
func siteAccessWrite(c siteconf.Config) (siteaccess.Settings, []edgeconfig.BasicAuthUser, error) {
	var doc siteAccessDocument
	if len(c.SiteAccess) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(c.SiteAccess))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&doc); err != nil {
			return siteaccess.Settings{}, nil, err
		}
	}
	settings := doc.Settings
	settings.BasicAuth = nil
	auth := doc.BasicAuth
	if auth == nil {
		return settings, nil, nil
	}
	check := edgeconfig.SiteAccess{BasicAuth: &edgeconfig.SiteBasicAuth{Realm: auth.Realm, Users: auth.Users,
		ExcludePathPrefixes: auth.ExcludePathPrefixes}}
	if err := edgeconfig.ValidateSiteAccess(check, nil, false); err != nil {
		return siteaccess.Settings{}, nil, err
	}
	settings.BasicAuth = &siteaccess.BasicAuth{Realm: auth.Realm, Users: []siteaccess.BasicAuthUser{},
		ExcludePathPrefixes: append([]string{}, auth.ExcludePathPrefixes...)}
	for _, user := range auth.Users {
		settings.BasicAuth.Users = append(settings.BasicAuth.Users, siteaccess.BasicAuthUser{Username: user.Username})
	}
	return settings, append([]edgeconfig.BasicAuthUser(nil), auth.Users...), nil
}

// siteAccessBlockers: a malformed site_access object, or one on a leaf
// without the site access service.
func (s *Service) siteAccessBlockers(c siteconf.Config) []siteconf.Blocker {
	if _, _, err := siteAccessWrite(c); err != nil {
		return []siteconf.Blocker{{Code: "site_access_invalid"}}
	}
	if len(c.SiteAccess) > 0 && s.access == nil {
		return []siteconf.Blocker{{Code: "unsupported_site_access"}}
	}
	return nil
}

// applySiteAccess writes the settings after the site is committed; equal
// stored settings are left alone, so a commit retry is idempotent.
func (s *Service) applySiteAccess(ctx context.Context, actor serviceActor, leafSiteID uuid.UUID, req siteconf.CommitRequest) error {
	settings, hashed, err := siteAccessWrite(req.Config)
	if err != nil {
		return err
	}
	if s.access == nil {
		if len(req.Config.SiteAccess) > 0 {
			return errors.New("market supply: site access settings are not configured")
		}
		return nil
	}
	accessActor := siteaccess.Actor{UserID: actor.userID, ScopeID: actor.scopeID, ScopeKind: "platform"}
	current, err := s.access.Get(ctx, accessActor, leafSiteID)
	if err != nil {
		return err
	}
	if sameSiteAccessState(current, settings, hashed) {
		return nil
	}
	key := "market-access-" + req.SiteID.String() + "-" + strconv.FormatInt(req.Revision, 10) + "-v" +
		strconv.FormatInt(current.Version, 10)
	_, err = s.access.Update(ctx, accessActor, siteaccess.UpdateRequest{SiteID: leafSiteID,
		ExpectedRevision: current.Version, Settings: settings, HashedUsers: hashed, IdempotencyKey: key, RequestID: key})
	return err
}

// sameSiteAccessState: the stored settings and basic auth hashes are the
// wanted ones.
func sameSiteAccessState(current siteaccess.State, settings siteaccess.Settings, hashed []edgeconfig.BasicAuthUser) bool {
	stored := current.BasicAuthUsers
	if len(stored) == 0 {
		stored = nil
	}
	if len(hashed) == 0 {
		hashed = nil
	}
	return sameSiteAccess(current.Settings, settings) && reflect.DeepEqual(stored, hashed)
}

// sameSiteAccess compares the stored and the wanted settings in their JSON
// form (nil and empty lists are the same; status 0 is 301).
func sameSiteAccess(stored, wanted siteaccess.Settings) bool {
	canonical := func(v siteaccess.Settings) map[string]any {
		if v.ForceHTTPS.Status == 0 {
			v.ForceHTTPS.Status = 301
		}
		raw, _ := json.Marshal(v)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		for key, value := range out {
			if list, ok := value.([]any); ok && len(list) == 0 || value == nil {
				delete(out, key)
			}
		}
		if force, ok := out["force_https"].(map[string]any); ok {
			if list, ok := force["exclude_hosts"].([]any); ok && len(list) == 0 || force["exclude_hosts"] == nil {
				delete(force, "exclude_hosts")
			}
		}
		return out
	}
	return reflect.DeepEqual(canonical(stored), canonical(wanted))
}
