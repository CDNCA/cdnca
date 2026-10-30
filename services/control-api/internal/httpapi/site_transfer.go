package httpapi

import (
	"net/http"

	"github.com/cdnca/cdnca/services/control-api/internal/site"
	"github.com/google/uuid"
)

// POST /v1/sites/{id}/transfer (fix-transfer): a platform administrator moves
// the site to another user. The site is re-created in the target user's
// tenant (new id, new CNAME) and the old one deleted in one transaction; the
// response is the new site and the old CNAME the customer must repoint from.
type transferSiteRequest struct {
	ExpectedVersion      int64      `json:"expected_version"`
	TargetUserID         uuid.UUID  `json:"target_user_id"`
	TargetSubscriptionID *uuid.UUID `json:"target_package_subscription_id"`
}

type transferSiteResponse struct {
	Site       siteDetailResponse `json:"site"`
	FromSiteID uuid.UUID          `json:"from_site_id"`
	FromCNAME  string             `json:"from_cname"`
	Copied     []string           `json:"copied"`
	Released   []string           `json:"released"`
}

func (s *Server) handleTransferSite(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requirePlatformSiteManage(w, r)
	if !ok {
		return
	}
	key, ok := s.idempotencyKey(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "validation_error", "site ID must be a UUID")
		return
	}
	var body transferSiteRequest
	if err := decodeJSON(w, r, &body); err != nil {
		s.writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "request body is invalid")
		return
	}
	// The platform session: the new site's CNAME intent and certificate
	// publication record it.
	actor, err := s.siteWriteActor(r, principal)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	result, err := s.sites.Transfer(r.Context(), actor, site.TransferRequest{
		ID: id, ExpectedRevision: body.ExpectedVersion, TargetUserID: body.TargetUserID,
		TargetSubscriptionID: body.TargetSubscriptionID, IdempotencyKey: key, RequestID: requestID(r.Context()),
	})
	if err != nil {
		s.writeSiteError(w, r, err)
		return
	}
	w.Header().Set("ETag", quoteVersion(result.Site.Revision))
	writeJSON(w, http.StatusCreated, transferSiteResponse{Site: siteDetail(result.Site), FromSiteID: result.FromSiteID,
		FromCNAME: result.FromCNAME, Copied: nonNilStrings(result.Copied), Released: nonNilStrings(result.Released)})
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
