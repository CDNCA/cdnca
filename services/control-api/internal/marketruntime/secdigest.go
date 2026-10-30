package marketruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/envelope"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/secdigest"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/google/uuid"
)

// Attack digests (ADR 0012 §19.1). As a leaf, every minute the runtime sends
// each settled 5-minute window of its market sites' attacks to the grants'
// root subscribers (operation supply.secdigest); as a subscriber, it hands
// received digests to DigestReceiver (marketsubscribe) instead of the leaf
// request handler.

const (
	digestStateFile = "market-secdigest.json"
	digestWindow    = secdigest.WindowSeconds * time.Second
	// digestSettle leaves late security events time to land (as attack alerts).
	digestSettle   = 2 * time.Minute
	digestCatchUp  = time.Hour
	digestInterval = time.Minute
)

// DigestSource is marketsupply.Service bound to the analytics readers.
type DigestSource interface {
	SecurityDigests(ctx context.Context, leaf uuid.UUID, start time.Time) ([]marketsupply.DigestTarget, error)
	Subscribers() map[string]uuid.UUID
	RememberSubscriber(key string, member uuid.UUID)
}

// DigestReceiver stores a verified digest relayed to this subscriber.
type DigestReceiver interface {
	ReceiveDigest(ctx context.Context, header envelope.Header, payload []byte) error
}

// WithSecDigest turns on the leaf side (source) and the subscriber side
// (receiver); either may be nil.
func (r *Runtime) WithSecDigest(source DigestSource, receiver DigestReceiver) *Runtime {
	r.digestSource, r.digestReceiver = source, receiver
	return r
}

type digestState struct {
	// Through is the end of the last window whose digests were all sent.
	Through time.Time `json:"through"`
	// Subscribers survive a restart; the grant fetch (rememberSubscribers)
	// refills them too.
	Subscribers map[string]uuid.UUID `json:"subscribers"`
}

func (r *Runtime) digestLoop(ctx context.Context) {
	r.restoreSubscribers()
	for {
		if err := r.sendDigests(ctx); err != nil && ctx.Err() == nil {
			r.log.Warn("market security digests failed", "err", err)
		}
		if !sleep(ctx, digestInterval) {
			return
		}
	}
}

// rememberSubscribers records the root subscriber the market names for each
// grant (GET /v1/grants), so a leaf knows where digests go right after a
// restart or for a grant no subscriber request has used yet.
func (r *Runtime) rememberSubscribers(grants []grant.Grant, subscribers map[uuid.UUID]uuid.UUID) {
	if r.digestSource == nil {
		return
	}
	for _, g := range grants {
		if member, ok := subscribers[g.GrantID]; ok {
			r.digestSource.RememberSubscriber(marketsupply.Key(g), member)
		}
	}
}

func (r *Runtime) restoreSubscribers() {
	state, err := r.loadDigestState()
	if err != nil {
		return
	}
	for key, member := range state.Subscribers {
		r.digestSource.RememberSubscriber(key, member)
	}
}

// sendDigests sends every settled window after the cursor (at most an hour
// back). A window's digests go out with a fixed message ID and idempotency
// key, so a retry after a lost answer is the same relay row; the cursor
// moves only once every digest of the window was accepted.
func (r *Runtime) sendDigests(ctx context.Context) error {
	self := r.identity()
	if self.MemberID == uuid.Nil {
		return nil
	}
	state, err := r.loadDigestState()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	latest := now.Add(-digestSettle).Truncate(digestWindow)
	start := state.Through
	if floor := latest.Add(-digestCatchUp); start.Before(floor) {
		start = floor
	}
	for ; !start.Add(digestWindow).After(latest); start = start.Add(digestWindow) {
		targets, err := r.digestSource.SecurityDigests(ctx, self.MemberID, start)
		if err != nil {
			return err
		}
		for _, t := range targets {
			if err := r.sendDigest(ctx, self, t); err != nil {
				return err
			}
		}
		state.Through = start.Add(digestWindow)
		state.Subscribers = r.digestSource.Subscribers()
		if err := r.saveDigestState(state); err != nil {
			return err
		}
	}
	// Keep newly learned subscribers even when no window closed.
	state.Subscribers = r.digestSource.Subscribers()
	return r.saveDigestState(state)
}

func (r *Runtime) sendDigest(ctx context.Context, self marketclient.Identity, t marketsupply.DigestTarget) error {
	signed, err := secdigest.Sign(t.Digest, self.SigningKey)
	if err != nil {
		return err
	}
	body, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	key := secdigest.IdempotencyKey(t.Digest.LeafSiteID, t.Digest.WindowStart)
	_, err = r.market.Send(ctx, self, marketclient.Outbound{To: t.Subscriber, GrantID: t.Grant.GrantID,
		MessageID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(self.MemberID.String()+"/"+key)), Operation: secdigest.Operation,
		Domains: t.Domains, IdempotencyKey: key, Payload: body})
	var rejected *marketclient.RejectedError
	if errors.As(err, &rejected) && rejected.Status/100 == 4 {
		// The market refused this one (grant revoked, subscriber gone):
		// it will never pass, and must not hold the other sites back.
		r.log.Warn("market security digest refused", "grant_id", t.Grant.GrantID, "status", rejected.Status, "code", rejected.Code)
		return nil
	}
	return err
}

func (r *Runtime) loadDigestState() (digestState, error) {
	var state digestState
	raw, err := os.ReadFile(filepath.Join(r.cfg.StateDir, digestStateFile))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if json.Unmarshal(raw, &state) != nil {
		// A corrupt state only costs re-sending (deduplicated) windows.
		return digestState{}, nil
	}
	return state, nil
}

func (r *Runtime) saveDigestState(state digestState) error {
	if err := os.MkdirAll(r.cfg.StateDir, 0o700); err != nil {
		return err
	}
	raw, _ := json.Marshal(state)
	tmp := filepath.Join(r.cfg.StateDir, digestStateFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(r.cfg.StateDir, digestStateFile))
}
