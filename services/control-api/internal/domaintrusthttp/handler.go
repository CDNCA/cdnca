// Package domaintrusthttp serves the domain blocklist (#11) and domain
// ownership (#12) endpoints.
//
// Tenant (account) routes, scope taken from the session:
//
//	GET    /v1/domain-ownerships                       verified/pending apexes with challenges
//	POST   /v1/domain-ownerships                       {domain, method} start or refresh a challenge
//	POST   /v1/domain-ownerships/check                 {domain} run the check now
//	POST   /v1/domain-ownerships/revoke                {domain}
//	GET    /v1/domain-ownerships/conflicts?domain=     other accounts' sites under a verified apex
//	POST   /v1/domain-ownerships/claims                {apex, domains} (Idempotency-Key)
//	GET    /v1/domain-ownerships/suspensions           this account's sites disabled by a claim
//
// Platform routes (domains.security.manage):
//
//	GET    /v1/admin/domain-blocklist?search=          entries
//	POST   /v1/admin/domain-blocklist                  create (Idempotency-Key)
//	PUT    /v1/admin/domain-blocklist/{id}             replace (Idempotency-Key, expected_revision)
//	DELETE /v1/admin/domain-blocklist/{id}?expected_revision=
//	POST   /v1/admin/domain-blocklist/import           {items:[...]} or text/plain lines
//	GET    /v1/admin/domain-blocklist/export           text/csv
//	GET    /v1/admin/domain-blocklist/hits?entry_id=   existing sites the list covers
//	GET    /v1/admin/domain-ownerships?apex=&status=
//	POST   /v1/admin/domain-ownerships/{id}/revoke
//	GET    /v1/admin/domain-claim-suspensions?include_released=
//	POST   /v1/admin/domain-claim-suspensions/{id}/release
package domaintrusthttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/domainblocklist"
	"github.com/cdnca/cdnca/services/control-api/internal/domainownership"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const maxBodyBytes = 512 << 10

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type AuthenticateSessionFunc func(context.Context, string) (identity.AuthenticatedSession, error)

// Patterns are the routes the control-api server forwards here.
var Patterns = []string{
	"GET /v1/domain-ownerships",
	"POST /v1/domain-ownerships",
	"POST /v1/domain-ownerships/check",
	"POST /v1/domain-ownerships/revoke",
	"GET /v1/domain-ownerships/conflicts",
	"POST /v1/domain-ownerships/claims",
	"GET /v1/domain-ownerships/suspensions",
	"GET /v1/admin/domain-blocklist",
	"POST /v1/admin/domain-blocklist",
	"PUT /v1/admin/domain-blocklist/{id}",
	"DELETE /v1/admin/domain-blocklist/{id}",
	"POST /v1/admin/domain-blocklist/import",
	"GET /v1/admin/domain-blocklist/export",
	"GET /v1/admin/domain-blocklist/hits",
	"GET /v1/admin/domain-ownerships",
	"POST /v1/admin/domain-ownerships/{id}/revoke",
	"GET /v1/admin/domain-claim-suspensions",
	"POST /v1/admin/domain-claim-suspensions/{id}/release",
}

type Handler struct {
	ownership    *domainownership.Service
	blocklist    *domainblocklist.Service
	authenticate AuthenticateSessionFunc
	mux          *http.ServeMux
}

func NewHandler(ownership *domainownership.Service, blocklist *domainblocklist.Service, authenticate AuthenticateSessionFunc) (*Handler, error) {
	if ownership == nil || blocklist == nil || authenticate == nil {
		return nil, errors.New("domain trust handler dependencies are required")
	}
	handler := &Handler{ownership: ownership, blocklist: blocklist, authenticate: authenticate, mux: http.NewServeMux()}
	routes := map[string]http.HandlerFunc{
		"GET /v1/domain-ownerships":                            handler.listOwnerships,
		"POST /v1/domain-ownerships":                           handler.startOwnership,
		"POST /v1/domain-ownerships/check":                     handler.checkOwnership,
		"POST /v1/domain-ownerships/revoke":                    handler.revokeOwnership,
		"GET /v1/domain-ownerships/conflicts":                  handler.conflicts,
		"POST /v1/domain-ownerships/claims":                    handler.claim,
		"GET /v1/domain-ownerships/suspensions":                handler.mySuspensions,
		"GET /v1/admin/domain-blocklist":                       handler.listBlocklist,
		"POST /v1/admin/domain-blocklist":                      handler.createBlocklist,
		"PUT /v1/admin/domain-blocklist/{id}":                  handler.updateBlocklist,
		"DELETE /v1/admin/domain-blocklist/{id}":               handler.deleteBlocklist,
		"POST /v1/admin/domain-blocklist/import":               handler.importBlocklist,
		"GET /v1/admin/domain-blocklist/export":                handler.exportBlocklist,
		"GET /v1/admin/domain-blocklist/hits":                  handler.blocklistHits,
		"GET /v1/admin/domain-ownerships":                      handler.adminOwnerships,
		"POST /v1/admin/domain-ownerships/{id}/revoke":         handler.adminRevoke,
		"GET /v1/admin/domain-claim-suspensions":               handler.adminSuspensions,
		"POST /v1/admin/domain-claim-suspensions/{id}/release": handler.adminRelease,
	}
	for _, pattern := range Patterns {
		handler.mux.HandleFunc(pattern, routes[pattern])
	}
	return handler, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	handler.mux.ServeHTTP(response, request)
}

type principal struct {
	userID, scopeID uuid.UUID
	kind            string
}

func (p principal) ownership() domainownership.Actor {
	return domainownership.Actor{UserID: p.userID, ScopeID: p.scopeID, ScopeKind: p.kind}
}
func (p principal) blocklist() domainblocklist.Actor {
	return domainblocklist.Actor{UserID: p.userID, ScopeID: p.scopeID, ScopeKind: p.kind}
}

// session authenticates the bearer token; the services authorize the scope
// and permission against the database in their own transaction.
func (handler *Handler) session(response http.ResponseWriter, request *http.Request, kind string) (principal, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || values[0][7:] == "" ||
		strings.TrimSpace(values[0][7:]) != values[0][7:] {
		writeError(response, request, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return principal{}, false
	}
	session, err := handler.authenticate(request.Context(), values[0][7:])
	if err != nil || session.Principal.UserID == uuid.Nil || session.SessionID == uuid.Nil {
		writeError(response, request, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return principal{}, false
	}
	if session.Principal.ScopeKind != kind {
		writeError(response, request, http.StatusForbidden, "permission_denied", "permission is required")
		return principal{}, false
	}
	return principal{userID: session.Principal.UserID, scopeID: session.Principal.ScopeID, kind: kind}, true
}

func requestID(request *http.Request) string {
	if id := request.Header.Get("X-Request-ID"); requestIDPattern.MatchString(id) {
		return id
	}
	return uuid.NewString()
}

func idempotencyKey(response http.ResponseWriter, request *http.Request) (string, bool) {
	keys := request.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !requestIDPattern.MatchString(keys[0]) {
		writeError(response, request, http.StatusBadRequest, "validation_error", "Idempotency-Key is required")
		return "", false
	}
	return keys[0], true
}

func decode(response http.ResponseWriter, request *http.Request, destination any) bool {
	contentType := strings.ToLower(request.Header.Get("Content-Type"))
	if !strings.HasPrefix(contentType, "application/json") {
		writeError(response, request, http.StatusUnsupportedMediaType, "unsupported_media_type", "JSON body is required")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxBodyBytes))
	if err != nil {
		writeError(response, request, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		writeError(response, request, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return false
	}
	return true
}

func pathID(response http.ResponseWriter, request *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(request.PathValue("id"))
	if err != nil || id == uuid.Nil {
		writeError(response, request, http.StatusBadRequest, "validation_error", "ID must be a UUID")
		return uuid.Nil, false
	}
	return id, true
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, request *http.Request, status int, code, message string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{
		"code": code, "message": message, "request_id": request.Header.Get("X-Request-ID"),
	}})
}

func writeServiceError(response http.ResponseWriter, request *http.Request, err error) {
	type mapping struct {
		target        error
		status        int
		code, message string
	}
	for _, item := range []mapping{
		{domainownership.ErrPermissionDenied, http.StatusForbidden, "permission_denied", "permission is required"},
		{domainownership.ErrInvalidInput, http.StatusBadRequest, "validation_error", "request fields are invalid"},
		{domainownership.ErrNotFound, http.StatusNotFound, "domain_ownership_not_found", "domain ownership was not found"},
		{domainownership.ErrPolicyOff, http.StatusConflict, "domain_ownership_disabled", "domain ownership verification is turned off"},
		{domainownership.ErrVerifiedByOther, http.StatusConflict, "domain_verified_by_other", "the domain ownership has been verified by another account"},
		{domainownership.ErrNotVerified, http.StatusConflict, "domain_ownership_not_verified", "verify ownership of the domain first"},
		{domainownership.ErrClaimRequiresTXT, http.StatusConflict, "domain_claim_requires_dns_txt", "claiming a domain requires DNS TXT verification"},
		{domainownership.ErrNoConflict, http.StatusConflict, "domain_claim_no_conflict", "no other account holds these domains"},
		{domainownership.ErrStillClaimed, http.StatusConflict, "domain_claim_still_held", "the claimant still serves this domain"},
		{domainownership.ErrBlocked, http.StatusUnprocessableEntity, "domain_blocked", "site domain is not allowed"},
		{domainownership.ErrRevisionConflict, http.StatusConflict, "version_conflict", "record changed concurrently, retry"},
		{domainownership.ErrIdempotencyConflict, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input"},
		{domainblocklist.ErrPermissionDenied, http.StatusForbidden, "permission_denied", "permission is required"},
		{domainblocklist.ErrInvalidInput, http.StatusBadRequest, "validation_error", "request fields are invalid"},
		{domainblocklist.ErrNotFound, http.StatusNotFound, "domain_blocklist_not_found", "blocklist entry was not found"},
		{domainblocklist.ErrConflict, http.StatusConflict, "domain_blocklist_conflict", "the pattern is already listed"},
		{domainblocklist.ErrRevisionConflict, http.StatusConflict, "version_conflict", "blocklist entry version is stale"},
		{domainblocklist.ErrIdempotencyConflict, http.StatusConflict, "idempotency_conflict", "idempotency key was already used with different input"},
	} {
		if errors.Is(err, item.target) {
			writeError(response, request, item.status, item.code, item.message)
			return
		}
	}
	writeError(response, request, http.StatusServiceUnavailable, "domain_trust_unavailable", "domain trust service is unavailable")
}

type domainRequest struct {
	Domain string `json:"domain"`
	Method string `json:"method,omitempty"`
}

func (handler *Handler) listOwnerships(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "tenant")
	if !ok {
		return
	}
	items, err := handler.ownership.List(request.Context(), actor.ownership())
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"items": items})
}

func (handler *Handler) startOwnership(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "tenant")
	if !ok {
		return
	}
	var body domainRequest
	if !decode(response, request, &body) {
		return
	}
	if body.Method == "" {
		body.Method = domainownership.MethodDNSTXT
	}
	item, err := handler.ownership.Start(request.Context(), actor.ownership(), body.Domain, body.Method, requestID(request))
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, item)
}

func (handler *Handler) checkOwnership(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "tenant")
	if !ok {
		return
	}
	var body domainRequest
	if !decode(response, request, &body) {
		return
	}
	item, err := handler.ownership.Check(request.Context(), actor.ownership(), body.Domain, requestID(request))
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, item)
}

func (handler *Handler) revokeOwnership(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "tenant")
	if !ok {
		return
	}
	var body domainRequest
	if !decode(response, request, &body) {
		return
	}
	item, err := handler.ownership.Revoke(request.Context(), actor.ownership(), body.Domain, requestID(request))
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, item)
}

func (handler *Handler) conflicts(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "tenant")
	if !ok {
		return
	}
	items, err := handler.ownership.Conflicts(request.Context(), actor.ownership(), request.URL.Query().Get("domain"))
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"items": items})
}

func (handler *Handler) claim(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "tenant")
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var body struct {
		Apex    string   `json:"apex"`
		Domains []string `json:"domains"`
	}
	if !decode(response, request, &body) {
		return
	}
	result, err := handler.ownership.Claim(request.Context(), actor.ownership(), domainownership.ClaimRequest{
		Apex: body.Apex, Domains: body.Domains, IdempotencyKey: key, RequestID: requestID(request),
	})
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) mySuspensions(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "tenant")
	if !ok {
		return
	}
	items, err := handler.ownership.ListMySuspensions(request.Context(), actor.ownership())
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"items": items})
}

func (handler *Handler) listBlocklist(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	items, err := handler.blocklist.List(request.Context(), actor.blocklist(), request.URL.Query().Get("search"), 0)
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"items": items})
}

func (handler *Handler) createBlocklist(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var body domainblocklist.Input
	if !decode(response, request, &body) {
		return
	}
	item, err := handler.blocklist.Create(request.Context(), actor.blocklist(), body, key, requestID(request))
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, item)
}

func (handler *Handler) updateBlocklist(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	id, ok := pathID(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var body struct {
		domainblocklist.Input
		ExpectedRevision int64 `json:"expected_revision"`
	}
	if !decode(response, request, &body) {
		return
	}
	item, err := handler.blocklist.Update(request.Context(), actor.blocklist(), id, body.ExpectedRevision, body.Input, key, requestID(request))
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, item)
}

func (handler *Handler) deleteBlocklist(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	id, ok := pathID(response, request)
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	revision, err := strconv.ParseInt(request.URL.Query().Get("expected_revision"), 10, 64)
	if err != nil {
		writeError(response, request, http.StatusBadRequest, "validation_error", "expected_revision is required")
		return
	}
	if err := handler.blocklist.Delete(request.Context(), actor.blocklist(), id, revision, key, requestID(request)); err != nil {
		writeServiceError(response, request, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

// importBlocklist accepts {"items":[{pattern,match_type,reason}]} or plain
// text, one "pattern[,match_type[,reason]]" per line (# starts a comment).
func (handler *Handler) importBlocklist(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	key, ok := idempotencyKey(response, request)
	if !ok {
		return
	}
	var items []domainblocklist.Input
	if strings.HasPrefix(strings.ToLower(request.Header.Get("Content-Type")), "text/") {
		raw, err := io.ReadAll(http.MaxBytesReader(response, request.Body, maxBodyBytes))
		if err != nil {
			writeError(response, request, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large")
			return
		}
		if items, err = parseLines(raw); err != nil {
			writeError(response, request, http.StatusBadRequest, "validation_error", err.Error())
			return
		}
	} else {
		var body struct {
			Items []domainblocklist.Input `json:"items"`
		}
		if !decode(response, request, &body) {
			return
		}
		items = body.Items
	}
	result, err := handler.blocklist.Import(request.Context(), actor.blocklist(), items, key, requestID(request))
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func parseLines(raw []byte) ([]domainblocklist.Input, error) {
	items := make([]domainblocklist.Input, 0)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		record, err := csv.NewReader(strings.NewReader(text)).Read()
		if err != nil || len(record) > 3 {
			return nil, errors.New("line " + strconv.Itoa(line) + " is invalid")
		}
		item := domainblocklist.Input{Pattern: strings.TrimSpace(record[0])}
		if len(record) > 1 {
			item.MatchType = strings.TrimSpace(record[1])
		}
		if len(record) > 2 {
			item.Reason = strings.TrimSpace(record[2])
		}
		items = append(items, item)
	}
	return items, scanner.Err()
}

func (handler *Handler) exportBlocklist(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	items, err := handler.blocklist.List(request.Context(), actor.blocklist(), "", 0)
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	response.Header().Set("Content-Type", "text/csv; charset=utf-8")
	response.Header().Set("Content-Disposition", `attachment; filename="domain-blocklist.csv"`)
	writer := csv.NewWriter(response)
	_ = writer.Write([]string{"pattern", "match_type", "reason"})
	for _, item := range items {
		reason := item.Reason
		if reason != "" && strings.ContainsRune("=+-@", rune(reason[0])) {
			reason = "'" + reason // keep spreadsheet formulas inert
		}
		_ = writer.Write([]string{item.Pattern, item.MatchType, reason})
	}
	writer.Flush()
}

func (handler *Handler) blocklistHits(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	id := uuid.Nil
	if raw := request.URL.Query().Get("entry_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			writeError(response, request, http.StatusBadRequest, "validation_error", "entry_id must be a UUID")
			return
		}
		id = parsed
	}
	hits, err := handler.blocklist.Hits(request.Context(), actor.blocklist(), id)
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"items": hits})
}

func (handler *Handler) adminOwnerships(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	query := request.URL.Query()
	items, err := handler.ownership.AdminListOwnerships(request.Context(), actor.ownership(), domainownership.AdminFilter{
		Apex: query.Get("apex"), Status: query.Get("status"),
	})
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"items": items})
}

func (handler *Handler) adminRevoke(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	id, ok := pathID(response, request)
	if !ok {
		return
	}
	item, err := handler.ownership.AdminRevokeOwnership(request.Context(), actor.ownership(), id, requestID(request))
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, item)
}

func (handler *Handler) adminSuspensions(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	items, err := handler.ownership.AdminListSuspensions(request.Context(), actor.ownership(),
		request.URL.Query().Get("include_released") == "true", 0)
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{"items": items})
}

func (handler *Handler) adminRelease(response http.ResponseWriter, request *http.Request) {
	actor, ok := handler.session(response, request, "platform")
	if !ok {
		return
	}
	id, ok := pathID(response, request)
	if !ok {
		return
	}
	item, err := handler.ownership.AdminReleaseSuspension(request.Context(), actor.ownership(), id, requestID(request))
	if err != nil {
		writeServiceError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, item)
}
