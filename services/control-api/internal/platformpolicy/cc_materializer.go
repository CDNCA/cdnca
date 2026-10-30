package platformpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// materializeEffectiveCCSystemRules projects the currently effective signed
// policy into the tenant-scoped CC reference tables. The reference tables are
// deliberately a projection: user-owned rows are never touched.
func materializeEffectiveCCSystemRules(ctx context.Context, tx pgx.Tx, installationID uuid.UUID, effectiveID *string, now time.Time) error {
	var rules []CCSystemRule
	var protection *CCProtection
	if effectiveID != nil {
		target, err := loadTarget(ctx, tx, *effectiveID)
		if err != nil {
			return err
		}
		if target.Signed.Policy != nil {
			rules = target.Signed.Policy.CCSystemRules
			protection = target.Signed.Policy.CCProtection
		}
	}
	return materializeCCSystemRules(ctx, tx, installationID, rules, protection, now)
}

func materializeCCSystemRules(ctx context.Context, tx pgx.Tx, _ uuid.UUID, rules []CCSystemRule, protection *CCProtection, now time.Time) error {
	// Older isolated platform-policy integration schemas predate the CC system-rule migration.
	// Production schemas always have these tables; keeping this compatibility
	// guard lets the policy store retain its standalone migration tests.
	var available bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('cc_reference_matchers') IS NOT NULL AND to_regclass('cc_reference_filters') IS NOT NULL`).Scan(&available); err != nil {
		return err
	}
	if !available {
		return nil
	}

	type scopeOwner struct {
		scopeID  uuid.UUID
		tenantID uuid.UUID
		ownerID  uuid.UUID
	}
	rows, err := tx.Query(ctx, `SELECT scope.id,scope.tenant_id,membership.user_id
		FROM access_scopes scope
		JOIN LATERAL (
			SELECT m.user_id
			FROM memberships m
			JOIN users account ON account.id=m.user_id AND account.status='active'
			WHERE m.scope_id=scope.id AND m.status='active'
			ORDER BY m.created_at,m.user_id
			LIMIT 1
		) membership ON true
		WHERE scope.kind='tenant' AND scope.tenant_id IS NOT NULL
		ORDER BY scope.id`)
	if err != nil {
		return fmt.Errorf("list tenant scopes for CC system rules: %w", err)
	}
	defer rows.Close()
	scopes := make([]scopeOwner, 0)
	for rows.Next() {
		var value scopeOwner
		if err := rows.Scan(&value.scopeID, &value.tenantID, &value.ownerID); err != nil {
			return err
		}
		scopes = append(scopes, value)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	matcherKeys := make([]string, 0, len(rules))
	filterKeys := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Matcher != nil {
			matcherKeys = append(matcherKeys, rule.Key)
		}
		if rule.Filter != nil {
			filterKeys = append(filterKeys, rule.Key)
		}
	}
	for _, scope := range scopes {
		for _, rule := range rules {
			switch {
			case rule.Matcher != nil:
				if err := upsertSystemMatcher(ctx, tx, scope, rule, now); err != nil {
					return err
				}
			case rule.Filter != nil:
				if err := upsertSystemFilter(ctx, tx, scope, rule, now); err != nil {
					return err
				}
			}
		}
		if err := retireSystemReferences(ctx, tx, "cc_reference_matchers", scope.scopeID, matcherKeys, now); err != nil {
			return err
		}
		if err := retireSystemReferences(ctx, tx, "cc_reference_filters", scope.scopeID, filterKeys, now); err != nil {
			return err
		}
		if protection != nil {
			if err := materializeCCProtection(ctx, tx, scope.scopeID, scope.ownerID, *protection, now); err != nil {
				return err
			}
		}
	}
	return nil
}

func materializeCCProtection(ctx context.Context, tx pgx.Tx, scopeID, ownerID uuid.UUID, protection CCProtection, now time.Time) error {
	var available bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('openresty_security_configs') IS NOT NULL AND to_regclass('openresty_security_config_revisions') IS NOT NULL AND to_regclass('openresty_security_publication_outbox') IS NOT NULL`).Scan(&available); err != nil {
		return err
	}
	if !available {
		return nil
	}
	current := openrestysecurity.DefaultGlobalConfig()
	var id uuid.UUID
	var revision int64
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT id,revision,document FROM openresty_security_configs WHERE tenant_scope_id=$1 AND scope_type='global' AND scope_id='0' AND deleted_at IS NULL FOR UPDATE`, scopeID).Scan(&id, &revision, &raw)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == nil {
		decoded, decodeErr := openrestysecurity.DecodeConfig(raw, false)
		if decodeErr != nil {
			return decodeErr
		}
		current = decoded
	} else {
		id = uuid.NewSHA1(uuid.NameSpaceOID, []byte(scopeID.String()+":global"))
	}
	patch := ccProtectionPatch(protection)
	next, err := openrestysecurity.ApplyPatch(current, patch, false)
	if err != nil {
		return err
	}
	encoded, digest, err := openrestysecurity.Canonical(next)
	if err != nil {
		return err
	}
	if revision > 0 && bytes.Equal(encoded, raw) {
		return nil
	}
	now = now.UTC().Truncate(time.Microsecond)
	nextRevision := revision + 1
	if revision == 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO openresty_security_configs(id,tenant_scope_id,scope_type,scope_id,document,document_sha256,key_override,revision,created_at,updated_at) VALUES($1,$2,'global','0',$3,$4,false,$5,$6,$6)`, id, scopeID, encoded, digest[:], nextRevision, now); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx, `UPDATE openresty_security_configs SET document=$3,document_sha256=$4,revision=$5,updated_at=$6 WHERE id=$1 AND tenant_scope_id=$2 AND scope_type='global' AND scope_id='0' AND revision=$7 AND deleted_at IS NULL`, id, scopeID, encoded, digest[:], nextRevision, now, revision); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO openresty_security_config_revisions(tenant_scope_id,config_id,revision,scope_type,scope_id,operation,document,document_sha256,key_configured,actor_scope_id,actor_user_id,request_id,created_at) VALUES($1,$2,$3,'global','0','global.patch',$4,$5,false,$1,$6,$7,$8)`, scopeID, id, nextRevision, encoded, digest[:], ownerID, "platform-policy.cc-protection", now); err != nil {
		return err
	}
	outboxID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO openresty_security_publication_outbox(id,tenant_scope_id,config_id,revision,scope_type,scope_id,operation,document,document_sha256,state,available_at,created_at,updated_at) VALUES($1,$2,$3,$4,'global','0','global.patch',$5,$6,'pending',$7,$7,$7)`, outboxID, scopeID, id, nextRevision, encoded, digest[:], now)
	return err
}

func ccProtectionPatch(protection CCProtection) openrestysecurity.Config {
	patch := openrestysecurity.Config{}
	for key, value := range map[string]any{
		"cc_enable": protection.CCEnable, "block_time": protection.BlockTime, "white_time": protection.WhiteTime,
		"tmp_white_total_limit": protection.TmpWhiteTotalLimit, "tmp_white_per_limit": protection.TmpWhitePerLimit,
		"default_page_rule": protection.DefaultPageRule, "auto_switch": protection.AutoSwitch,
		"slider_html": protection.Templates.SliderHTML, "captcha_html": protection.Templates.CaptchaHTML,
		"click_html": protection.Templates.ClickHTML, "delay_jump_html": protection.Templates.DelayJumpHTML,
		"rotate_html": protection.Templates.RotateHTML, "easy_click_html": protection.Templates.EasyClickHTML,
		"easy_slider_html": protection.Templates.EasySliderHTML,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			return openrestysecurity.Config{}
		}
		patch[key] = encoded
	}
	return patch
}

func upsertSystemMatcher(ctx context.Context, tx pgx.Tx, scope struct {
	scopeID  uuid.UUID
	tenantID uuid.UUID
	ownerID  uuid.UUID
}, rule CCSystemRule, now time.Time) error {
	values, err := json.Marshal(rule.Matcher.Values)
	if err != nil {
		return err
	}
	document, err := json.Marshal(map[string]any{
		"name": rule.Name, "sort": rule.Sort, "system_rule": true, "system_rule_id": rule.ID, "system_rule_sort": rule.Sort, "system_rule_key": rule.Key,
		"field": rule.Matcher.Field, "operator": rule.Matcher.Operator, "key": rule.Matcher.Key,
		"values": rule.Matcher.Values,
	})
	if err != nil {
		return err
	}
	var id uuid.UUID
	var revision int64
	var oldDeleted *time.Time
	err = tx.QueryRow(ctx, `SELECT id,revision,deleted_at FROM cc_reference_matchers
		WHERE scope_id=$1 AND system_rule_key=$2 ORDER BY (deleted_at IS NULL) DESC,updated_at DESC,id DESC LIMIT 1 FOR UPDATE`, scope.scopeID, rule.Key).Scan(&id, &revision, &oldDeleted)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == pgx.ErrNoRows {
		id, err = uuid.NewV7()
		if err != nil {
			return err
		}
		revision = 1
		if _, err := tx.Exec(ctx, `INSERT INTO cc_reference_matchers(
			id,scope_id,tenant_id,owner_user_id,name,description,field,operator,condition_key,values,
			enabled,revision,created_by_user_id,updated_by_user_id,created_at,updated_at,system_rule,system_rule_id,system_rule_sort,system_rule_key)
			VALUES($1,$2,$3,$4,$5,'',$6,$7,$8,$9,true,1,$4,$4,$10,$10,true,$11,$12,$13)`,
			id, scope.scopeID, scope.tenantID, scope.ownerID, rule.Name, rule.Matcher.Field, rule.Matcher.Operator,
			rule.Matcher.Key, values, now.UTC(), rule.ID, rule.Sort, rule.Key); err != nil {
			return err
		}
	} else {
		restored := oldDeleted != nil
		changed := restored
		var previous string
		if err := tx.QueryRow(ctx, `SELECT name||'|'||description||'|'||field||'|'||operator||'|'||condition_key||'|'||values::text||'|'||owner_user_id::text FROM cc_reference_matchers WHERE id=$1`, id).Scan(&previous); err != nil {
			return err
		}
		want := fmt.Sprintf("%s||%s|%s|%s|%s|%s", rule.Name, rule.Matcher.Field, rule.Matcher.Operator, rule.Matcher.Key, string(values), scope.ownerID)
		changed = changed || previous != want
		if _, err := tx.Exec(ctx, `UPDATE cc_reference_matchers SET scope_id=$2,tenant_id=$3,owner_user_id=$4,name=$5,description='',field=$6,operator=$7,condition_key=$8,values=$9,
				revision=CASE WHEN $10 THEN revision+1 ELSE revision END,updated_by_user_id=$4,updated_at=CASE WHEN $10 THEN $12 ELSE updated_at END,
				deleted_at=NULL,system_rule=true,system_rule_id=$13,system_rule_sort=$14,system_rule_key=$15,enabled=CASE WHEN $11 THEN true ELSE enabled END WHERE id=$1`,
			id, scope.scopeID, scope.tenantID, scope.ownerID, rule.Name, rule.Matcher.Field, rule.Matcher.Operator, rule.Matcher.Key, values, changed, restored, now.UTC(), rule.ID, rule.Sort, rule.Key); err != nil {
			return err
		}
	}
	revision, err = revisionForMaterialized(ctx, tx, "cc_reference_matchers", id)
	if err != nil {
		return err
	}
	return insertSystemVersion(ctx, tx, "matcher", id, revision, document, scope.ownerID, now)
}

func upsertSystemFilter(ctx context.Context, tx pgx.Tx, scope struct {
	scopeID  uuid.UUID
	tenantID uuid.UUID
	ownerID  uuid.UUID
}, rule CCSystemRule, now time.Time) error {
	parameters, err := json.Marshal(rule.Filter.Parameters)
	if err != nil {
		return err
	}
	document, err := json.Marshal(map[string]any{
		"name": rule.Name, "sort": rule.Sort, "system_rule": true, "system_rule_id": rule.ID, "system_rule_sort": rule.Sort, "system_rule_key": rule.Key,
		"type": rule.Filter.Type, "parameters": rule.Filter.Parameters,
	})
	if err != nil {
		return err
	}
	var id uuid.UUID
	var revision int64
	var oldDeleted *time.Time
	err = tx.QueryRow(ctx, `SELECT id,revision,deleted_at FROM cc_reference_filters
		WHERE scope_id=$1 AND system_rule_key=$2 ORDER BY (deleted_at IS NULL) DESC,updated_at DESC,id DESC LIMIT 1 FOR UPDATE`, scope.scopeID, rule.Key).Scan(&id, &revision, &oldDeleted)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == pgx.ErrNoRows {
		id, err = uuid.NewV7()
		if err != nil {
			return err
		}
		revision = 1
		if _, err := tx.Exec(ctx, `INSERT INTO cc_reference_filters(
			id,scope_id,tenant_id,owner_user_id,name,description,filter_type,parameters,enabled,revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at,system_rule,system_rule_id,system_rule_sort,system_rule_key)
			VALUES($1,$2,$3,$4,$5,'',$6,$7,true,1,$4,$4,$8,$8,true,$9,$10,$11)`,
			id, scope.scopeID, scope.tenantID, scope.ownerID, rule.Name, rule.Filter.Type, parameters, now.UTC(), rule.ID, rule.Sort, rule.Key); err != nil {
			return err
		}
	} else {
		restored := oldDeleted != nil
		changed := restored
		var previous string
		if err := tx.QueryRow(ctx, `SELECT name||'|'||description||'|'||filter_type||'|'||parameters::text||'|'||owner_user_id::text FROM cc_reference_filters WHERE id=$1`, id).Scan(&previous); err != nil {
			return err
		}
		want := fmt.Sprintf("%s||%s|%s|%s", rule.Name, rule.Filter.Type, string(parameters), scope.ownerID)
		changed = changed || previous != want
		if _, err := tx.Exec(ctx, `UPDATE cc_reference_filters SET scope_id=$2,tenant_id=$3,owner_user_id=$4,name=$5,description='',filter_type=$6,parameters=$7,
				revision=CASE WHEN $8 THEN revision+1 ELSE revision END,updated_by_user_id=$4,updated_at=CASE WHEN $8 THEN $10 ELSE updated_at END,
				deleted_at=NULL,system_rule=true,system_rule_id=$11,system_rule_sort=$12,system_rule_key=$13,enabled=CASE WHEN $9 THEN true ELSE enabled END WHERE id=$1`,
			id, scope.scopeID, scope.tenantID, scope.ownerID, rule.Name, rule.Filter.Type, parameters, changed, restored, now.UTC(), rule.ID, rule.Sort, rule.Key); err != nil {
			return err
		}
	}
	revision, err = revisionForMaterialized(ctx, tx, "cc_reference_filters", id)
	if err != nil {
		return err
	}
	return insertSystemVersion(ctx, tx, "filter", id, revision, document, scope.ownerID, now)
}

func revisionForMaterialized(ctx context.Context, tx pgx.Tx, table string, id uuid.UUID) (int64, error) {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM `+table+` WHERE id=$1`, id).Scan(&revision); err != nil {
		return 0, err
	}
	return revision, nil
}

func insertSystemVersion(ctx context.Context, tx pgx.Tx, kind string, id uuid.UUID, revision int64, document []byte, owner uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO cc_reference_versions(reference_kind,reference_id,revision,document,created_by_user_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(reference_kind,reference_id,revision) DO NOTHING`, kind, id, revision, document, owner, now.UTC())
	return err
}

func retireSystemReferences(ctx context.Context, tx pgx.Tx, table string, scopeID uuid.UUID, keys []string, now time.Time) error {
	query := `UPDATE ` + table + ` SET enabled=false,deleted_at=$2,revision=revision+1,updated_at=$2
		WHERE scope_id=$1 AND system_rule=true AND deleted_at IS NULL`
	args := []any{scopeID, now.UTC()}
	if len(keys) > 0 {
		query += ` AND system_rule_key <> ALL($3::text[])`
		args = append(args, keys)
	}
	_, err := tx.Exec(ctx, query, args...)
	return err
}
