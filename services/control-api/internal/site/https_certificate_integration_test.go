//go:build integration

package site

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// be-gap-2 WEB-C01/C05（待出包前全量跑）：没绑证书时不能打开 HTTPS 或强制跳转；
// 绑定后可以打开；详情带 https_certificate_bound；已开启的站点解绑后其他字段仍能保存。
func TestHTTPSRequiresBoundCertificatePostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	created, err := f.createSite(f.a, f.a, "https-gate.example.test")
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.sites.Get(ctx, f.a.siteActor(), created.Site.ID)
	if err != nil || current.HTTPSCertificateBound {
		t.Fatalf("new site bound=%v err=%v", current.HTTPSCertificateBound, err)
	}
	fields := SiteFields{Domains: current.Domains, HTTPPorts: []string{"80"}, HTTPSPorts: []string{"443"}, HTTPSEnabled: true,
		Origins: []string{"192.0.2.1"}, Enabled: true, Status: StatusActive}
	update := func(key string, fields SiteFields) (WriteResult, error) {
		return f.sites.Update(ctx, f.a.siteActor(), UpdateRequest{ID: current.ID, ExpectedRevision: current.Revision,
			Fields: fields, IdempotencyKey: key, RequestID: key})
	}
	var fieldErr *FieldError
	if _, err := update("https-on-unbound", fields); !errors.As(err, &fieldErr) || fieldErr.Field != "https_enabled" ||
		fieldErr.Reason != ReasonCertificateRequired {
		t.Fatalf("HTTPS on without certificate err=%v", err)
	}
	if after, _ := f.sites.Get(ctx, f.a.siteActor(), current.ID); after.HTTPSEnabled || after.Revision != current.Revision {
		t.Fatalf("refused update was stored: %+v", after)
	}

	// A bound certificate (the fact the certificate service appends; FKs to the asset tables are skipped here).
	bindFact := func(action string, sequence int64) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO certificate_site_binding_facts (tenant_scope_id,site_id,sequence,action,asset_id,version_id,
				is_default,expected_revision,resulting_revision,request_id,actor_scope_id,changed_by_user_id,changed_at)
				VALUES ($1,$2,$3,$4,$5,$6,true,$7,$3,$8,$1,$9,now())`, f.a.scopeID, current.ID, sequence, action, uuid.New(), uuid.New(),
				sequence-1, "bind-"+action, f.a.userID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	bindFact("bind", 1)
	if got, _ := f.sites.Get(ctx, f.a.siteActor(), current.ID); !got.HTTPSCertificateBound {
		t.Fatal("bound site reports no certificate")
	}
	on := true
	fields.ForceHTTPS = &on
	opened, err := update("https-on-bound", fields)
	if err != nil || !opened.Site.HTTPSEnabled || !opened.Site.ForceHTTPS || !opened.Site.HTTPSCertificateBound {
		t.Fatalf("HTTPS on with certificate = %+v %v", opened.Site, err)
	}
	current = opened.Site

	// Unbound later: HTTPS stays as it is and the site's other edits still save.
	bindFact("unbind", 2)
	fields.Origins = []string{"192.0.2.1"}
	fields.Domains = current.Domains
	kept, err := update("https-kept-unbound", fields)
	if err != nil || !kept.Site.HTTPSEnabled || kept.Site.HTTPSCertificateBound {
		t.Fatalf("edit after unbind = %+v %v", kept.Site, err)
	}
}
