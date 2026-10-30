package edgeartifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// Site objects (ADR 0009 §8.3) are served by digest to the node a site
// runtime v8 deployment targets: the deployment must still be fetchable (as
// FetchChunk), its command must name the requested root, and every digest
// must be a member of the publication that root names. Objects are immutable
// and content addressed, so a fetch needs no audit row to be retried.

const (
	// MaxSiteObjectsPerRequest is agent.v1.FetchSiteObjectsRequest's bound.
	MaxSiteObjectsPerRequest = 256
	// siteObjectMemberCacheEntries bounds the per-process publication
	// member cache (one entry per recent config version).
	siteObjectMemberCacheEntries = 16
)

var (
	ErrSiteObjectNotMember = errors.New("site object is not a member of the deployment's publication")
	digestHexPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// SiteObjectChunkSink receives the response chunks in order.
type SiteObjectChunkSink func(*controlv1.FetchSiteObjectsResponse) error

type siteObjectAuthorization struct {
	scopeID  uuid.UUID
	keyEpoch int64
	digests  [][]byte
}

type siteObjectMembers struct {
	configID uuid.UUID
	scopeID  uuid.UUID
	keyEpoch int64
	root     []byte
	members  []byte
}

type siteObjectMemberCache struct {
	mu      sync.Mutex
	entries []siteObjectMembers
}

func (cache *siteObjectMemberCache) get(configID uuid.UUID) (siteObjectMembers, bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for _, entry := range cache.entries {
		if entry.configID == configID {
			return entry, true
		}
	}
	return siteObjectMembers{}, false
}

func (cache *siteObjectMemberCache) put(entry siteObjectMembers) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.entries = append(cache.entries, entry)
	if len(cache.entries) > siteObjectMemberCacheEntries {
		cache.entries = cache.entries[len(cache.entries)-siteObjectMemberCacheEntries:]
	}
}

// contains reports whether digest is in members (ascending 32-byte digests).
func (members siteObjectMembers) contains(digest []byte) bool {
	count := len(members.members) / sha256.Size
	index := sort.Search(count, func(i int) bool {
		return bytes.Compare(members.members[i*sha256.Size:(i+1)*sha256.Size], digest) >= 0
	})
	return index < count && bytes.Equal(members.members[index*sha256.Size:(index+1)*sha256.Size], digest)
}

// FetchSiteObjects authorizes request and streams each requested object's
// wire bytes, whole and in request order, in chunks of at most
// Config.MaxChunkBytes.
func (s *Store) FetchSiteObjects(ctx context.Context, request *controlv1.FetchSiteObjectsRequest, send SiteObjectChunkSink) error {
	if ctx == nil || send == nil {
		return fmt.Errorf("%w: context or sink", ErrInvalidRequest)
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	normalized, err := normalizeSiteObjectsRequest(request, s.config, now)
	if err != nil {
		return err
	}
	var authorization siteObjectAuthorization
	var domainErr error
	err = pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			authorization, domainErr, err = s.authorizeSiteObjects(ctx, tx, normalized, now)
			return err
		})
	if err != nil {
		return fmt.Errorf("%w: transaction: %w", ErrStorage, err)
	}
	if domainErr != nil {
		return domainErr
	}
	// Objects are immutable: they are read after the authorization
	// transaction, one at a time, so a slow node does not hold it open.
	for index, digest := range authorization.digests {
		var wire []byte
		if err := s.pool.QueryRow(ctx, `SELECT ciphertext FROM edge_site_objects
			WHERE configuration_scope_id=$1 AND key_epoch=$2 AND sha256=$3`,
			authorization.scopeID, authorization.keyEpoch, digest).Scan(&wire); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: publication member %x is not stored", ErrArtifactIntegrity, digest)
			}
			return fmt.Errorf("%w: read site object: %w", ErrStorage, err)
		}
		if len(wire) < 16 || len(wire) > siteobject.MaxObjectBytes+16 {
			return fmt.Errorf("%w: site object size", ErrArtifactIntegrity)
		}
		name := request.Sha256[index]
		for offset := 0; offset < len(wire); offset += s.config.MaxChunkBytes {
			end := min(offset+s.config.MaxChunkBytes, len(wire))
			if err := send(&controlv1.FetchSiteObjectsResponse{Chunk: &agentv1.SiteObjectChunk{
				RequestId: normalized.requestID.String(), Sha256: name, Offset: uint64(offset),
				Data: bytes.Clone(wire[offset:end]), TotalSizeBytes: uint64(len(wire)), EndOfObject: end == len(wire),
			}}); err != nil {
				return err
			}
		}
	}
	return nil
}

type normalizedSiteObjectsRequest struct {
	requestID, eventID, nodeID, deploymentID uuid.UUID
	attempt                                  int32
	root                                     []byte
	digests                                  [][]byte
}

func normalizeSiteObjectsRequest(request *controlv1.FetchSiteObjectsRequest, config Config, now time.Time) (normalizedSiteObjectsRequest, error) {
	invalid := func(what string) (normalizedSiteObjectsRequest, error) {
		return normalizedSiteObjectsRequest{}, fmt.Errorf("%w: %s", ErrInvalidRequest, what)
	}
	if request == nil || len(request.ProtoReflect().GetUnknown()) != 0 ||
		proto.Size(request) > config.MaxRequestBytes+MaxSiteObjectsPerRequest*(2+64) {
		return invalid("message")
	}
	metadata := request.Request
	if metadata == nil || len(metadata.ProtoReflect().GetUnknown()) != 0 || metadata.SentTime == nil ||
		metadata.SentTime.CheckValid() != nil {
		return invalid("request metadata")
	}
	sentAt := metadata.SentTime.AsTime()
	if sentAt.After(now.Add(config.MaxFutureSkew)) || sentAt.Before(now.Add(-config.MaxRequestAge)) {
		return invalid("request time")
	}
	if !validTraceparent(metadata.Traceparent) {
		return invalid("traceparent")
	}
	var result normalizedSiteObjectsRequest
	var err error
	for _, field := range []struct {
		value  string
		target *uuid.UUID
	}{{metadata.RequestId, &result.requestID}, {request.EventId, &result.eventID}, {request.NodeId, &result.nodeID},
		{request.DeploymentId, &result.deploymentID}} {
		if *field.target, err = canonicalUUID(field.value); err != nil {
			return invalid("identifier")
		}
	}
	if _, err := canonicalUUID(request.GatewayInstanceId); err != nil {
		return invalid("gateway instance ID")
	}
	if request.Attempt == 0 || uint64(request.Attempt) > math.MaxInt32 {
		return invalid("attempt")
	}
	result.attempt = int32(request.Attempt)
	if !digestHexPattern.MatchString(request.RootSha256) || len(request.Sha256) == 0 ||
		len(request.Sha256) > MaxSiteObjectsPerRequest {
		return invalid("digests")
	}
	result.root, _ = hex.DecodeString(request.RootSha256)
	seen := make(map[string]struct{}, len(request.Sha256))
	for _, value := range request.Sha256 {
		if !digestHexPattern.MatchString(value) {
			return invalid("digest")
		}
		if _, duplicate := seen[value]; duplicate {
			return invalid("duplicate digest")
		}
		seen[value] = struct{}{}
		digest, _ := hex.DecodeString(value)
		result.digests = append(result.digests, digest)
	}
	return result, nil
}

// authorizeSiteObjects returns the scope/epoch to read and the digests in
// request order, or a domain error.
func (s *Store) authorizeSiteObjects(ctx context.Context, tx pgx.Tx, request normalizedSiteObjectsRequest,
	now time.Time) (siteObjectAuthorization, error, error) {
	var (
		nodeID, eventID, configID, scopeID uuid.UUID
		action, state, configStatus        string
		deadline                           time.Time
		newer                              bool
		commandBytes, commandSHA256        []byte
	)
	err := tx.QueryRow(ctx, `SELECT deployment.node_id,deployment.command_event_id,deployment.config_version_id,
		config.configuration_scope_id,deployment.action,deployment.state,config.status,deployment.deadline_at,
		EXISTS(SELECT 1 FROM node_deployments newer WHERE newer.id=deployment.id AND newer.attempt>deployment.attempt),
		deployment.command_bytes,deployment.command_sha256
		FROM node_deployments deployment JOIN config_versions config ON config.id=deployment.config_version_id
		WHERE deployment.id=$1 AND deployment.attempt=$2`, request.deploymentID, request.attempt).Scan(
		&nodeID, &eventID, &configID, &scopeID, &action, &state, &configStatus, &deadline, &newer,
		&commandBytes, &commandSHA256)
	if errors.Is(err, pgx.ErrNoRows) {
		return siteObjectAuthorization{}, ErrBindingConflict, nil
	}
	if err != nil {
		return siteObjectAuthorization{}, nil, fmt.Errorf("read site object deployment: %w", err)
	}
	if nodeID != request.nodeID || eventID != request.eventID {
		return siteObjectAuthorization{}, ErrBindingConflict, nil
	}
	if newer || action != "apply" || !fetchableDeploymentState(state) ||
		configStatus != "releasable" && configStatus != "superseded" || !deadline.After(now) {
		return siteObjectAuthorization{}, ErrDeploymentIneligible, nil
	}
	digest := sha256.Sum256(commandBytes)
	if len(commandBytes) == 0 || len(commandBytes) > 1<<20 || !bytes.Equal(digest[:], commandSHA256) {
		return siteObjectAuthorization{}, fmt.Errorf("%w: deployment command digest", ErrArtifactIntegrity), nil
	}
	command := new(agentv1.DeploymentCommand)
	if err := proto.Unmarshal(commandBytes, command); err != nil || command.DeploymentId != request.deploymentID.String() ||
		command.ConfigVersionId != configID.String() || len(command.Artifacts) != 2 || command.Artifacts[0] == nil ||
		command.Artifacts[0].MediaType != siteobject.RootMediaTypeV2 {
		// Not a site object deployment: nothing to fetch.
		return siteObjectAuthorization{}, ErrBindingConflict, nil
	}
	if !bytes.Equal(command.Artifacts[0].Sha256, request.root) {
		return siteObjectAuthorization{}, ErrBindingConflict, nil
	}
	members, found := s.siteObjectMembers.get(configID)
	if !found {
		if err := tx.QueryRow(ctx, `SELECT root_sha256,member_sha256,key_epoch FROM edge_site_object_publications
			WHERE config_version_id=$1 AND configuration_scope_id=$2`, configID, scopeID).Scan(
			&members.root, &members.members, &members.keyEpoch); errors.Is(err, pgx.ErrNoRows) {
			return siteObjectAuthorization{}, ErrBindingConflict, nil
		} else if err != nil {
			return siteObjectAuthorization{}, nil, fmt.Errorf("read site object publication: %w", err)
		}
		if members.keyEpoch < 1 || len(members.members) == 0 || len(members.members)%sha256.Size != 0 {
			return siteObjectAuthorization{}, fmt.Errorf("%w: site object publication", ErrArtifactIntegrity), nil
		}
		members.configID, members.scopeID = configID, scopeID
		s.siteObjectMembers.put(members)
	}
	if !bytes.Equal(members.root, request.root) || members.scopeID != scopeID {
		return siteObjectAuthorization{}, ErrBindingConflict, nil
	}
	for _, digest := range request.digests {
		if !members.contains(digest) {
			return siteObjectAuthorization{}, ErrSiteObjectNotMember, nil
		}
	}
	return siteObjectAuthorization{scopeID: scopeID, keyEpoch: members.keyEpoch, digests: slices.Clone(request.digests)}, nil, nil
}
