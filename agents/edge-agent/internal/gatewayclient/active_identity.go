package gatewayclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const activeConfigIdentityAPIVersion uint32 = 1

const deploymentStatusAckReceiptAPIVersion uint32 = 1

const deploymentStatusStream = "AGENT_DEPLOYMENT_STATUS"

// These hard limits bound every retained journal entry, proof name, intent, and
// byte of top-level journal metadata before any recovery mutation is attempted.
const (
	deploymentJournalReadBatch          = 32
	deploymentJournalEntryLimit         = 1024
	deploymentJournalAggregateByteLimit = int64(256 << 20)
)

const (
	deploymentStatusAckVersion        = 1
	deploymentStatusAckSuffix         = ".deployment-ack"
	deploymentStatusAckReceiptVersion = 1
	deploymentStatusAckReceiptSuffix  = ".deployment-ack-receipt"
	legacyDeploymentStatusSentVersion = 1
	legacyDeploymentStatusSentSuffix  = ".legacy-deployment-sent"
	deploymentCompactionIntentVersion = 1
	deploymentCompactionIntentSuffix  = ".deployment-compaction"
)

type deploymentHistory struct {
	records []*durableRecord
	replay  []*durableRecord
}

type durableDeploymentStatusAck struct {
	Version            int    `json:"version"`
	RecordKey          string `json:"record_key"`
	StatusEventID      string `json:"status_event_id"`
	DeploymentID       string `json:"deployment_id"`
	Attempt            uint32 `json:"attempt"`
	ConfigVersionID    string `json:"config_version_id"`
	TransitionSequence uint64 `json:"transition_sequence"`
	PersistedUnixNano  int64  `json:"persisted_unix_nano,omitempty"`
	PublishedStream    string `json:"published_stream,omitempty"`
	PublishedSequence  uint64 `json:"published_sequence,omitempty"`
	ReceiptRequired    bool   `json:"receipt_required,omitempty"`
	ReceiptConfirmed   bool   `json:"receipt_confirmed,omitempty"`
}

type durableDeploymentStatusAckReceipt struct {
	Version            int    `json:"version"`
	RecordKey          string `json:"record_key"`
	StatusEventID      string `json:"status_event_id"`
	DeploymentID       string `json:"deployment_id"`
	Attempt            uint32 `json:"attempt"`
	ConfigVersionID    string `json:"config_version_id"`
	TransitionSequence uint64 `json:"transition_sequence"`
	PersistedUnixNano  int64  `json:"persisted_unix_nano"`
	PublishedStream    string `json:"published_stream,omitempty"`
	PublishedSequence  uint64 `json:"published_sequence,omitempty"`
	SessionEpoch       uint64 `json:"session_epoch,omitempty"`
	StreamSequence     uint64 `json:"stream_sequence,omitempty"`
}

type pendingDeploymentStatusAckReceipt struct {
	recordKey string
	receipt   *agentv1.DeploymentStatusAckReceipt
}

type durableLegacyDeploymentStatusSent struct {
	Version            int    `json:"version"`
	RecordKey          string `json:"record_key"`
	SessionEpoch       uint64 `json:"session_epoch"`
	StreamSequence     uint64 `json:"stream_sequence"`
	StatusEventID      string `json:"status_event_id"`
	DeploymentID       string `json:"deployment_id"`
	Attempt            uint32 `json:"attempt"`
	ConfigVersionID    string `json:"config_version_id"`
	TransitionSequence uint64 `json:"transition_sequence"`
}

type durableDeploymentCompactionIntent struct {
	Version            int    `json:"version"`
	RecordKey          string `json:"record_key"`
	StatusEventID      string `json:"status_event_id"`
	DeploymentID       string `json:"deployment_id"`
	Attempt            uint32 `json:"attempt"`
	ConfigVersionID    string `json:"config_version_id"`
	TransitionSequence uint64 `json:"transition_sequence"`
}

type durablePathSnapshot struct {
	name      string
	info      os.FileInfo
	digest    [sha256.Size]byte
	hasDigest bool
	maxSize   int64
}

type deploymentCompactionSnapshot struct {
	directory  *os.File
	artifacts  *os.File
	intents    []deploymentCompactionSnapshotEntry
	cleanup    []deploymentCompactionCleanupSnapshot
	proofNames []string
	proofs     []durablePathSnapshot
}

type deploymentJournalInventory struct {
	entries []os.FileInfo
}

type deploymentCompactionSnapshotEntry struct {
	intent       *durableDeploymentCompactionIntent
	ack          *durableDeploymentStatusAck
	intentPath   durablePathSnapshot
	ackPath      durablePathSnapshot
	recordPath   durablePathSnapshot
	markerPath   durablePathSnapshot
	artifactPath durablePathSnapshot
}

type deploymentCompactionCleanupSnapshot struct {
	path   durablePathSnapshot
	guards []durablePathSnapshot
}

type deploymentResultLookup interface {
	Lookup(string) (deployment.Result, bool, error)
}

type activeConfigIdentityState struct {
	mu          sync.Mutex
	initialized bool
	key         [sha256.Size]byte
	current     *agentv1.ActiveConfigIdentity
	previous    *agentv1.ActiveConfigIdentity
}

func activeConfigIdentityCapability() *agentv1.Capability {
	return &agentv1.Capability{
		Name:       agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY,
		ApiVersion: activeConfigIdentityAPIVersion,
	}
}

func deploymentStatusAckReceiptCapability() *agentv1.Capability {
	return &agentv1.Capability{
		Name:       agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT,
		ApiVersion: deploymentStatusAckReceiptAPIVersion,
	}
}

func ensureActiveConfigIdentityCapability(capabilities *agentv1.AgentCapabilities) error {
	for _, capability := range capabilities.Features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY {
			continue
		}
		if capability.ApiVersion != activeConfigIdentityAPIVersion {
			return ErrInvalidConfiguration
		}
		return nil
	}
	if len(capabilities.Features) >= 64 {
		return ErrInvalidConfiguration
	}
	capabilities.Features = append(capabilities.Features, activeConfigIdentityCapability())
	return nil
}

func ensureDeploymentStatusAckReceiptCapability(capabilities *agentv1.AgentCapabilities) error {
	for _, capability := range capabilities.Features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT {
			continue
		}
		if capability.ApiVersion != deploymentStatusAckReceiptAPIVersion {
			return ErrInvalidConfiguration
		}
		return nil
	}
	if len(capabilities.Features) >= 64 {
		return ErrInvalidConfiguration
	}
	capabilities.Features = append(capabilities.Features, deploymentStatusAckReceiptCapability())
	return nil
}

func gatewayHelloHasActiveIdentityV1(hello *agentv1.GatewayHello) bool {
	if hello == nil {
		return false
	}
	for _, capability := range hello.EnabledCapabilities {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_ACTIVE_CONFIG_IDENTITY && capability.ApiVersion == activeConfigIdentityAPIVersion {
			return true
		}
	}
	return false
}

func gatewayHelloHasDeploymentStatusAckReceiptV1(hello *agentv1.GatewayHello) bool {
	if hello == nil {
		return false
	}
	for _, capability := range hello.EnabledCapabilities {
		if capability != nil && capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_DEPLOYMENT_STATUS_ACK_RECEIPT && capability.ApiVersion == deploymentStatusAckReceiptAPIVersion {
			return true
		}
	}
	return false
}

func (c *Client) activeConfigIdentities(pointers deployment.Pointers, records []*durableRecord) (*agentv1.ActiveConfigIdentity, *agentv1.ActiveConfigIdentity) {
	runtimeKey, runtimeUncertain := c.activeConfigRuntimeUncertain(pointers, records)
	key := activeConfigIdentitySnapshotKey(pointers, records, runtimeKey)
	c.activeIdentity.mu.Lock()
	defer c.activeIdentity.mu.Unlock()
	if c.activeIdentity.initialized && c.activeIdentity.key == key {
		return cloneActiveConfigIdentity(c.activeIdentity.current), cloneActiveConfigIdentity(c.activeIdentity.previous)
	}
	current := c.activeConfigIdentity(pointers.Current, pointers.CurrentDigest, records)
	previous := c.activeConfigIdentity(pointers.Previous, pointers.PreviousDigest, records)
	if runtimeUncertain {
		current = nil
	}
	c.activeIdentity.initialized = true
	c.activeIdentity.key = key
	c.activeIdentity.current = cloneActiveConfigIdentity(current)
	c.activeIdentity.previous = cloneActiveConfigIdentity(previous)
	return cloneActiveConfigIdentity(current), cloneActiveConfigIdentity(previous)
}

func activeConfigIdentitySnapshotKey(pointers deployment.Pointers, records []*durableRecord, runtimeKey [sha256.Size]byte) [sha256.Size]byte {
	hash := sha256.New()
	writePart := func(value []byte) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write(value)
	}
	for _, value := range []string{pointers.Current, pointers.CurrentDigest, pointers.Previous, pointers.PreviousDigest} {
		writePart([]byte(value))
	}
	writePart(runtimeKey[:])
	for _, record := range records {
		if record == nil {
			writePart(nil)
			continue
		}
		writePart([]byte(record.RecordKey))
		writePart([]byte(record.CommandDigest))
		var offset [8]byte
		binary.BigEndian.PutUint64(offset[:], record.ArtifactOffset)
		writePart(offset[:])
		if record.ExecutionDone {
			writePart([]byte{1})
		} else {
			writePart([]byte{0})
		}
		for _, encoded := range record.Statuses {
			digest := sha256.Sum256(encoded)
			writePart(digest[:])
		}
	}
	var key [sha256.Size]byte
	copy(key[:], hash.Sum(nil))
	return key
}

func (c *Client) activeConfigRuntimeUncertain(pointers deployment.Pointers, records []*durableRecord) ([sha256.Size]byte, bool) {
	runtimeHash := sha256.New()
	writeRuntimePart := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = runtimeHash.Write(size[:])
		_, _ = runtimeHash.Write([]byte(value))
	}
	uncertain := false
	for _, record := range records {
		if record == nil {
			continue
		}
		command := commandFromBytes(record.Command)
		if command == nil {
			return [sha256.Size]byte{}, true
		}
		relevant := record.ConfigVersionID == pointers.Current
		if command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK && command.GetPreviousConfigVersionId() == pointers.Current {
			relevant = true
		}
		if !record.ExecutionDone &&
			(command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY || command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_RECONCILE) &&
			command.GetPreviousConfigVersionId() == pointers.Current {
			relevant = true
		}
		if !relevant {
			continue
		}
		if !record.ExecutionDone {
			if command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK &&
				command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY &&
				command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_RECONCILE {
				continue
			}
			writeRuntimePart(record.RecordKey)
			lookup, supported := c.manager.(deploymentResultLookup)
			if !supported {
				writeRuntimePart("unsupported")
				return digestHash(runtimeHash), true
			}
			result, managerFound, err := lookup.Lookup(record.DeploymentID)
			if err != nil {
				writeRuntimePart("error")
				return digestHash(runtimeHash), true
			}
			if !managerFound {
				writeRuntimePart("not-found")
				continue
			}
			writeRuntimePart(string(result.State))
			writeRuntimePart(result.ErrorCode)
			if result.RunningConfigUnchanged {
				writeRuntimePart("unchanged")
			} else {
				writeRuntimePart("changed")
			}
			wantAction := deployment.ActionApply
			if command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK {
				wantAction = deployment.ActionRollback
			}
			if result.DeploymentID != record.DeploymentID || result.Attempt != record.Attempt ||
				result.Action != wantAction || result.ConfigVersionID != record.ConfigVersionID {
				return digestHash(runtimeHash), true
			}
			if wantAction == deployment.ActionApply {
				switch result.State {
				case deployment.StateDelivered, deployment.StateStaged, deployment.StateHealthy, deployment.StateReverted:
				case deployment.StateFailed:
					if !result.RunningConfigUnchanged {
						return digestHash(runtimeHash), true
					}
				case deployment.StatePrechecked, deployment.StateActivated, deployment.StateReverting, deployment.StateRollbackFailed:
					return digestHash(runtimeHash), true
				default:
					return digestHash(runtimeHash), true
				}
			} else {
				switch result.State {
				case deployment.StateDelivered, deployment.StateStaged, deployment.StatePrechecked, deployment.StateReverted:
				case deployment.StateFailed:
					if !result.RunningConfigUnchanged {
						return digestHash(runtimeHash), true
					}
				case deployment.StateReverting, deployment.StateRollbackFailed:
					return digestHash(runtimeHash), true
				default:
					return digestHash(runtimeHash), true
				}
			}
			continue
		}
		statuses, err := statusesFromRecord(record)
		if err != nil || len(statuses) == 0 {
			return digestHash(runtimeHash), true
		}
		final := statuses[len(statuses)-1]
		writeRuntimePart(record.RecordKey)
		writeRuntimePart(final.State.String())
		if final.Event == nil {
			return digestHash(runtimeHash), true
		}
		if final.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED {
			uncertain = true
		}
	}
	return digestHash(runtimeHash), uncertain
}

func digestHash(hash interface{ Sum([]byte) []byte }) [sha256.Size]byte {
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func (c *Client) activeConfigIdentity(configVersionID, manifestSHA256 string, records []*durableRecord) *agentv1.ActiveConfigIdentity {
	if !canonicalUUID(configVersionID) || len(manifestSHA256) != sha256.Size*2 {
		return nil
	}
	var identity *agentv1.ActiveConfigIdentity
	for _, record := range records {
		command := commandFromBytes(record.Command)
		if command == nil || command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY || command.ConfigVersionId != configVersionID || configurationDescriptor(command) == nil {
			continue
		}
		candidate := c.verifiedActiveConfigIdentity(record, command, configurationDescriptor(command), manifestSHA256)
		if candidate == nil {
			continue
		}
		if identity != nil && !bytes.Equal(identity.ArtifactSha256, candidate.ArtifactSha256) {
			return nil
		}
		identity = candidate
	}
	return cloneActiveConfigIdentity(identity)
}

// configurationDescriptor is the artifact a configuration deployment's
// active identity names: its only artifact, or a site object deployment's
// root.
func configurationDescriptor(command *agentv1.DeploymentCommand) *agentv1.ArtifactDescriptor {
	if len(command.Artifacts) == 1 || isSiteObjectCommand(command) {
		return command.Artifacts[0]
	}
	return nil
}

func (c *Client) verifiedActiveConfigIdentity(record *durableRecord, command *agentv1.DeploymentCommand, descriptor *agentv1.ArtifactDescriptor, manifestSHA256 string, completing ...*agentv1.DeploymentStatus) *agentv1.ActiveConfigIdentity {
	if record == nil || descriptor == nil || descriptor.Kind != agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION ||
		len(descriptor.Sha256) != sha256.Size || record.ArtifactOffset != descriptor.SizeBytes ||
		!c.healthyActiveConfigRecord(record, command, completing...) {
		return nil
	}
	wireBytes, err := c.store.readArtifact(record.RecordKey, descriptor.SizeBytes)
	if err != nil {
		return nil
	}
	digest := sha256.Sum256(wireBytes)
	if !bytes.Equal(digest[:], descriptor.Sha256) || verifyArtifactSignature(descriptor, wireBytes, c.trust) != nil {
		return nil
	}
	if isDynamicRoutingCommand(command) {
		// A dynamic routing root names no bundle: the scope pointer's digest
		// is the root's own (DynamicRoutingRelease.RootSHA256).
		if _, err := siteobject.ParseRootV2(wireBytes); err != nil || hex.EncodeToString(digest[:]) != manifestSHA256 {
			return nil
		}
		return &agentv1.ActiveConfigIdentity{
			ConfigVersionId: command.ConfigVersionId,
			ArtifactSha256:  append([]byte(nil), descriptor.Sha256...),
			Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		}
	}
	payload := wireBytes
	if descriptor.EncryptionAlgorithm == agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM {
		payload, err = decryptArtifactHPKE(command, descriptor, wireBytes, c.config.ArtifactDecryptionPrivateKey)
		if err != nil {
			return nil
		}
		defer clearPlaintext(payload)
	} else if descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE {
		return nil
	}
	decoded, err := decompressArtifact(descriptor.Compression, payload, c.config.MaxDecompressedBytes)
	if err != nil {
		return nil
	}
	if descriptor.EncryptionAlgorithm != agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE {
		defer clearPlaintext(decoded)
	}
	bundle, err := decodeConfigurationBundle(decoded)
	if err != nil || bundle.ManifestSHA256 != manifestSHA256 {
		return nil
	}
	return &agentv1.ActiveConfigIdentity{
		ConfigVersionId: command.ConfigVersionId,
		ArtifactSha256:  append([]byte(nil), descriptor.Sha256...),
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
	}
}

func (c *Client) healthyActiveConfigRecord(record *durableRecord, command *agentv1.DeploymentCommand, completing ...*agentv1.DeploymentStatus) bool {
	if record == nil || command == nil || command.Action != agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY || len(completing) > 1 {
		return false
	}
	var final *agentv1.DeploymentStatus
	if len(completing) == 1 {
		final = completing[0]
	} else {
		if !record.ExecutionDone {
			return false
		}
		statuses, err := statusesFromRecord(record)
		if err != nil || len(statuses) == 0 {
			return false
		}
		final = statuses[len(statuses)-1]
	}
	if final == nil || final.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY ||
		final.DeploymentId != record.DeploymentID || final.Attempt != record.Attempt || final.ConfigVersionId != record.ConfigVersionID {
		return false
	}
	lookup, supported := c.manager.(deploymentResultLookup)
	if !supported {
		return false
	}
	result, found, err := lookup.Lookup(record.DeploymentID)
	return err == nil && found && result.DeploymentID == record.DeploymentID && result.Attempt == record.Attempt &&
		result.Action == deployment.ActionApply && result.ConfigVersionID == record.ConfigVersionID && result.State == deployment.StateHealthy
}

func sameDeploymentPointers(left, right deployment.Pointers) bool {
	return left.Current == right.Current && left.CurrentDigest == right.CurrentDigest &&
		left.Previous == right.Previous && left.PreviousDigest == right.PreviousDigest
}

func (c *Client) stableActiveConfigSnapshot() (deployment.Pointers, deploymentHistory, error) {
	for range 3 {
		before, err := c.historyPointerSets()
		if err != nil {
			return deployment.Pointers{}, deploymentHistory{}, err
		}
		history, err := c.deploymentHistoryFor(before)
		if err != nil {
			return deployment.Pointers{}, deploymentHistory{}, err
		}
		after, err := c.historyPointerSets()
		if err != nil {
			return deployment.Pointers{}, deploymentHistory{}, err
		}
		if samePointerSets(before, after) {
			pointers, err := c.manager.Pointers()
			if err != nil {
				return deployment.Pointers{}, deploymentHistory{}, err
			}
			return pointers, history, nil
		}
	}
	return deployment.Pointers{}, deploymentHistory{}, fmt.Errorf("active config pointers changed during snapshot construction")
}

func samePointerSets(left, right []deployment.Pointers) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !sameDeploymentPointers(left[index], right[index]) {
			return false
		}
	}
	return true
}

func (c *Client) deploymentHistory(pointers deployment.Pointers) (deploymentHistory, error) {
	return c.deploymentHistoryFor([]deployment.Pointers{pointers})
}

// deploymentHistoryFor compacts the journal while keeping the identity and
// runtime evidence of every pointer set: one set on a single-scope node, one
// per configuration scope on a multi-scope node.
func (c *Client) deploymentHistoryFor(pointerSets []deployment.Pointers) (deploymentHistory, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if err := c.store.recoverDeploymentCompactionsLocked(); err != nil {
		return deploymentHistory{}, err
	}

	replay := make([]*durableRecord, 0, c.config.MaxActiveDeployments)
	identityRecords := make(map[string]map[string]*durableRecord, 2)
	healthyIdentityRecords := make(map[string]*durableRecord, 2)
	runtimeRecords := make([]map[string]*durableRecord, len(pointerSets))
	for index := range runtimeRecords {
		runtimeRecords[index] = make(map[string]*durableRecord, 1)
	}
	// Config version IDs are unique, so one version names at most one scope.
	manifestByVersion := make(map[string]string, 2*len(pointerSets))
	for _, pointers := range pointerSets {
		if pointers.Current != "" {
			manifestByVersion[pointers.Current] = pointers.CurrentDigest
		}
		if pointers.Previous != "" {
			manifestByVersion[pointers.Previous] = pointers.PreviousDigest
		}
	}
	keep := make(map[string]*durableRecord, 8)
	type receiptMutation struct {
		recordKey string
		receipt   *durableDeploymentStatusAckReceipt
		remove    bool
	}
	receiptMutations := make([]receiptMutation, 0)

	err := c.store.scanDeploymentRecordsLocked(func(record *durableRecord) error {
		ack, err := c.store.loadDeploymentStatusAckLocked(record.RecordKey)
		if err != nil {
			return err
		}
		if ack != nil {
			if err := validateDeploymentStatusAckRecord(ack, record); err != nil {
				return err
			}
			if ack.ReceiptRequired && ack.PersistedUnixNano > 0 {
				receipt, err := c.store.loadDeploymentStatusAckReceiptLocked(record.RecordKey)
				if err != nil {
					return err
				}
				if ack.ReceiptConfirmed {
					if receipt != nil {
						if err := validateDeploymentStatusAckReceiptRecord(receipt, record); err != nil {
							return err
						}
						receiptMutations = append(receiptMutations, receiptMutation{recordKey: record.RecordKey, remove: true})
					}
				} else if receipt == nil {
					receipt = deploymentStatusAckReceiptForAck(ack)
					receiptMutations = append(receiptMutations, receiptMutation{recordKey: record.RecordKey, receipt: receipt})
				}
				if !ack.ReceiptConfirmed {
					if err := validateDeploymentStatusAckReceiptRecord(receipt, record); err != nil {
						return err
					}
					keep[record.RecordKey] = cloneRecord(record)
				}
			}
		}
		if !record.ExecutionDone {
			replay = append(replay, cloneRecord(record))
			if len(replay) > c.config.MaxActiveDeployments {
				return fmt.Errorf("active deployment history exceeds its limit")
			}
			return nil
		}
		command := commandFromBytes(record.Command)
		if command == nil {
			return fmt.Errorf("gateway journal command is corrupt")
		}
		manifestDigest, pointed := manifestByVersion[record.ConfigVersionID]
		if command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY &&
			pointed && configurationDescriptor(command) != nil &&
			c.healthyActiveConfigRecord(record, command) {
			if existing := healthyIdentityRecords[record.ConfigVersionID]; existing == nil || record.RecordKey < existing.RecordKey {
				healthyIdentityRecords[record.ConfigVersionID] = cloneRecord(record)
			}
			identity := c.verifiedActiveConfigIdentity(record, command, configurationDescriptor(command), manifestDigest)
			if identity != nil {
				byDigest := identityRecords[record.ConfigVersionID]
				if byDigest == nil {
					byDigest = make(map[string]*durableRecord, 2)
					identityRecords[record.ConfigVersionID] = byDigest
				}
				digest := hex.EncodeToString(identity.ArtifactSha256)
				if existing := byDigest[digest]; existing == nil || record.RecordKey < existing.RecordKey {
					byDigest[digest] = cloneRecord(record)
				}
				if len(byDigest) > 2 {
					digests := make([]string, 0, len(byDigest))
					for candidateDigest := range byDigest {
						digests = append(digests, candidateDigest)
					}
					sort.Strings(digests)
					for _, candidateDigest := range digests[2:] {
						delete(byDigest, candidateDigest)
					}
				}
			}
		}

		for index, pointers := range pointerSets {
			relevant := record.ConfigVersionID == pointers.Current ||
				command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK && command.GetPreviousConfigVersionId() == pointers.Current
			if !relevant {
				continue
			}
			statuses, err := statusesFromRecord(record)
			if err != nil || len(statuses) == 0 {
				return fmt.Errorf("gateway journal status is corrupt")
			}
			final := statuses[len(statuses)-1]
			if !terminalDeploymentState(final.State) {
				return fmt.Errorf("gateway journal terminal status is corrupt")
			}
			if final.Event == nil || final.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED {
				// Keep the lowest record key per pointer set, as before.
				replace := true
				for key := range runtimeRecords[index] {
					if key < record.RecordKey {
						replace = false
						break
					}
					delete(runtimeRecords[index], key)
				}
				if replace {
					runtimeRecords[index][record.RecordKey] = cloneRecord(record)
				}
			}
		}
		return nil
	})
	if err != nil {
		return deploymentHistory{}, err
	}
	sort.Slice(receiptMutations, func(i, j int) bool { return receiptMutations[i].recordKey < receiptMutations[j].recordKey })
	removedReceipt := false
	for _, mutation := range receiptMutations {
		if mutation.remove {
			if err := removeDurablePath(filepath.Join(c.store.directory, mutation.recordKey+deploymentStatusAckReceiptSuffix)); err != nil {
				return deploymentHistory{}, err
			}
			removedReceipt = true
			continue
		}
		if err := c.store.saveDeploymentStatusAckReceiptLocked(mutation.receipt); err != nil {
			return deploymentHistory{}, err
		}
	}
	if removedReceipt {
		if err := syncDirectory(c.store.directory); err != nil {
			return deploymentHistory{}, err
		}
	}

	for _, byDigest := range identityRecords {
		for _, record := range byDigest {
			keep[record.RecordKey] = record
		}
	}
	for configVersionID, record := range healthyIdentityRecords {
		if len(identityRecords[configVersionID]) == 0 {
			keep[record.RecordKey] = record
		}
	}
	for _, perScope := range runtimeRecords {
		for key, record := range perScope {
			keep[key] = record
		}
	}
	if err := c.store.compactAcknowledgedDeploymentRecordsLocked(keep); err != nil {
		return deploymentHistory{}, err
	}
	records := append([]*durableRecord(nil), replay...)
	for _, record := range keep {
		records = append(records, cloneRecord(record))
	}
	sortDeploymentRecords(records)
	sortDeploymentRecords(replay)
	return deploymentHistory{records: records, replay: replay}, nil
}

func (c *Client) acknowledgeDeploymentStatus(ack *agentv1.DeploymentStatusAck) error {
	if err := c.store.acknowledgeDeploymentStatus(ack); err != nil {
		return err
	}
	_, err := c.refreshDeploymentHistory()
	return err
}

func (c *Client) persistDeploymentStatusAckReceipt(ack *agentv1.DeploymentStatusAck) (*agentv1.DeploymentStatusAckReceipt, error) {
	if err := c.store.acknowledgeDeploymentStatus(ack, true); err != nil {
		return nil, err
	}
	key := recordKey(ack.DeploymentId, ack.Attempt)
	c.store.mu.Lock()
	marker, err := c.store.loadDeploymentStatusAckLocked(key)
	var result *agentv1.DeploymentStatusAckReceipt
	if err == nil && marker == nil {
		err = fmt.Errorf("%w: deployment acknowledgement is missing", ErrInvalidMessage)
	}
	if err == nil && !marker.ReceiptConfirmed {
		var receipt *durableDeploymentStatusAckReceipt
		receipt, err = c.store.loadDeploymentStatusAckReceiptLocked(key)
		if err == nil && receipt == nil {
			receipt = deploymentStatusAckReceiptForAck(marker)
			err = c.store.saveDeploymentStatusAckReceiptLocked(receipt)
		}
		if err == nil {
			result = deploymentStatusAckReceiptProto(receipt)
		}
	}
	c.store.mu.Unlock()
	if err != nil {
		return nil, err
	}
	_, err = c.refreshDeploymentHistory()
	return result, err
}

func (c *Client) acknowledgeLegacyDeploymentStatuses(sessionEpoch, heartbeatSequence uint64) error {
	if sessionEpoch == 0 || heartbeatSequence == 0 {
		return fmt.Errorf("%w: invalid legacy deployment acknowledgement barrier", ErrInvalidMessage)
	}
	if err := c.store.promoteLegacyDeploymentStatuses(sessionEpoch, heartbeatSequence); err != nil {
		return err
	}
	_, err := c.refreshDeploymentHistory()
	return err
}

func (s *durableStore) disableDeploymentStatusAckReceipts() error {
	return s.disableDeploymentStatusAckReceiptsWithHook(nil)
}

func (s *durableStore) disableDeploymentStatusAckReceiptsWithHook(beforeMutation func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := boundedDeploymentJournalEntriesAt(directory)
	if err != nil {
		return err
	}
	inventory := deploymentJournalInventory{entries: append([]os.FileInfo(nil), entries...)}
	records := make(map[string]*durableRecord)
	acks := make(map[string]*durableDeploymentStatusAck)
	receipts := make(map[string]durablePathSnapshot)
	validatedPaths := make([]durablePathSnapshot, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		switch {
		case journalSiblingStateFile(name):
			continue
		case filepath.Ext(name) == ".json":
			key := strings.TrimSuffix(name, ".json")
			if len(key) != sha256.Size*2 {
				return fmt.Errorf("unexpected gateway journal file")
			}
			record, path, err := s.loadDeploymentRecordAt(directory, key)
			if err != nil || record == nil || path.info == nil || !os.SameFile(entry, path.info) {
				return fmt.Errorf("gateway journal record changed during downgrade validation")
			}
			records[key] = record
			validatedPaths = append(validatedPaths, path)
		case strings.HasSuffix(name, deploymentStatusAckSuffix):
			key := strings.TrimSuffix(name, deploymentStatusAckSuffix)
			ack, path, err := loadDeploymentStatusAckAt(directory, key)
			if err != nil || ack == nil || path.info == nil || !os.SameFile(entry, path.info) {
				return fmt.Errorf("deployment acknowledgement file is invalid")
			}
			acks[key] = ack
			validatedPaths = append(validatedPaths, path)
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, deploymentStatusAckReceiptSuffix) {
			continue
		}
		key := strings.TrimSuffix(name, deploymentStatusAckReceiptSuffix)
		decodedKey, decodeErr := hex.DecodeString(key)
		if decodeErr != nil || len(decodedKey) != sha256.Size || hex.EncodeToString(decodedKey) != key {
			return fmt.Errorf("deployment acknowledgement receipt file is invalid")
		}
		receipt, path, err := loadDeploymentStatusAckReceiptAt(directory, key)
		if err != nil || receipt == nil || path.info == nil || !os.SameFile(entry, path.info) {
			return fmt.Errorf("deployment acknowledgement receipt file is invalid")
		}
		record := records[key]
		ack := acks[key]
		if record == nil || ack == nil || !ack.ReceiptRequired || ack.ReceiptConfirmed {
			return fmt.Errorf("deployment acknowledgement receipt has no exact required acknowledgement")
		}
		if err := validateDeploymentStatusAckRecord(ack, record); err != nil {
			return err
		}
		expected := deploymentStatusAckReceiptForAck(ack)
		expected.SessionEpoch = receipt.SessionEpoch
		expected.StreamSequence = receipt.StreamSequence
		if *receipt != *expected {
			return fmt.Errorf("deployment acknowledgement receipt does not match its durable acknowledgement")
		}
		receipts[key] = path
		validatedPaths = append(validatedPaths, path)
	}
	type downgrade struct {
		ack         *durableDeploymentStatusAck
		receiptPath durablePathSnapshot
	}
	downgrades := make([]downgrade, 0)
	for key, ack := range acks {
		record := records[key]
		if record == nil {
			continue
		}
		if err := validateDeploymentStatusAckRecord(ack, record); err != nil {
			return err
		}
		if ack.ReceiptRequired {
			downgrades = append(downgrades, downgrade{ack: ack, receiptPath: receipts[key]})
		}
	}
	sort.Slice(downgrades, func(i, j int) bool { return downgrades[i].ack.RecordKey < downgrades[j].ack.RecordKey })
	if beforeMutation != nil {
		beforeMutation()
	}
	if err := inventory.verify(directory); err != nil {
		return err
	}
	for _, path := range validatedPaths {
		if err := verifyDurablePathAt(directory, path); err != nil {
			return err
		}
	}
	for _, downgrade := range downgrades {
		ack := downgrade.ack
		if downgrade.receiptPath.info != nil {
			if err := removeDurablePathAt(directory, downgrade.receiptPath); err != nil {
				return err
			}
			if err := directory.Sync(); err != nil {
				return err
			}
		}
		ack.ReceiptRequired = false
		ack.ReceiptConfirmed = false
		if err := s.saveDeploymentStatusAckLocked(ack); err != nil {
			return err
		}
	}
	return nil
}

func (s *durableStore) acknowledgeDeploymentStatus(ack *agentv1.DeploymentStatusAck, requireReceipt ...bool) error {
	if ack == nil || cacheControlMessageHasUnknown(ack.ProtoReflect()) || !canonicalUUID(ack.StatusEventId) ||
		!canonicalUUID(ack.DeploymentId) || ack.Attempt == 0 || !safeIdentifier(ack.ConfigVersionId) ||
		ack.TransitionSequence == 0 || ack.PersistedTime == nil || ack.PersistedTime.CheckValid() != nil ||
		(ack.PublishedStream == "") != (ack.PublishedSequence == 0) ||
		ack.PublishedStream != "" && ack.PublishedStream != deploymentStatusStream ||
		len(requireReceipt) == 1 && requireReceipt[0] && (ack.PublishedStream == "" || ack.PublishedSequence == 0) {
		return fmt.Errorf("%w: invalid deployment status acknowledgement", ErrInvalidMessage)
	}
	key := recordKey(ack.DeploymentId, ack.Attempt)
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.loadLocked(key)
	if err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("%w: deployment acknowledgement has no durable record", ErrInvalidMessage)
	}
	marker := &durableDeploymentStatusAck{
		Version: deploymentStatusAckVersion, RecordKey: key, StatusEventID: ack.StatusEventId,
		DeploymentID: ack.DeploymentId, Attempt: ack.Attempt, ConfigVersionID: ack.ConfigVersionId,
		TransitionSequence: ack.TransitionSequence, PersistedUnixNano: ack.PersistedTime.AsTime().UTC().UnixNano(),
		PublishedStream: ack.PublishedStream, PublishedSequence: ack.PublishedSequence,
		ReceiptRequired: len(requireReceipt) == 1 && requireReceipt[0],
	}
	if err := validateDeploymentStatusAckRecord(marker, record); err != nil {
		return err
	}
	existing, err := s.loadDeploymentStatusAckLocked(key)
	if err != nil {
		return err
	}
	if existing != nil {
		if *existing == *marker {
			return nil
		}
		existingWithoutTime, markerWithoutTime := *existing, *marker
		existingWithoutTime.PersistedUnixNano = 0
		markerWithoutTime.PersistedUnixNano = 0
		existingWithoutTime.ReceiptRequired = false
		markerWithoutTime.ReceiptRequired = false
		existingWithoutTime.ReceiptConfirmed = false
		markerWithoutTime.ReceiptConfirmed = false
		if existing.ReceiptConfirmed && existingWithoutTime == markerWithoutTime && existing.PersistedUnixNano == marker.PersistedUnixNano {
			return nil
		}
		if existing.PersistedUnixNano == 0 && existingWithoutTime == markerWithoutTime {
			return s.saveDeploymentStatusAckLocked(marker)
		}
		if !existing.ReceiptRequired && marker.ReceiptRequired && existingWithoutTime == markerWithoutTime && existing.PersistedUnixNano == marker.PersistedUnixNano {
			return s.saveDeploymentStatusAckLocked(marker)
		}
		return fmt.Errorf("%w: deployment acknowledgement conflicts with durable state", ErrInvalidMessage)
	}
	return s.saveDeploymentStatusAckLocked(marker)
}

func deploymentStatusAckReceiptForAck(ack *durableDeploymentStatusAck) *durableDeploymentStatusAckReceipt {
	if ack == nil {
		return nil
	}
	return &durableDeploymentStatusAckReceipt{
		Version: deploymentStatusAckReceiptVersion, RecordKey: ack.RecordKey, StatusEventID: ack.StatusEventID,
		DeploymentID: ack.DeploymentID, Attempt: ack.Attempt, ConfigVersionID: ack.ConfigVersionID,
		TransitionSequence: ack.TransitionSequence, PersistedUnixNano: ack.PersistedUnixNano,
		PublishedStream: ack.PublishedStream, PublishedSequence: ack.PublishedSequence,
	}
}

func deploymentStatusAckReceiptProto(receipt *durableDeploymentStatusAckReceipt) *agentv1.DeploymentStatusAckReceipt {
	if receipt == nil {
		return nil
	}
	return &agentv1.DeploymentStatusAckReceipt{
		StatusEventId: receipt.StatusEventID, DeploymentId: receipt.DeploymentID, Attempt: receipt.Attempt,
		ConfigVersionId: receipt.ConfigVersionID, TransitionSequence: receipt.TransitionSequence,
		PersistedTime:   timestamppb.New(time.Unix(0, receipt.PersistedUnixNano).UTC()),
		PublishedStream: receipt.PublishedStream, PublishedSequence: receipt.PublishedSequence,
	}
}

func validateDeploymentStatusAckReceiptRecord(receipt *durableDeploymentStatusAckReceipt, record *durableRecord) error {
	if err := validateDurableDeploymentStatusAckReceipt(receipt); err != nil {
		return err
	}
	ack := &durableDeploymentStatusAck{
		Version: deploymentStatusAckVersion, RecordKey: receipt.RecordKey, StatusEventID: receipt.StatusEventID,
		DeploymentID: receipt.DeploymentID, Attempt: receipt.Attempt, ConfigVersionID: receipt.ConfigVersionID,
		TransitionSequence: receipt.TransitionSequence, PersistedUnixNano: receipt.PersistedUnixNano,
		PublishedStream: receipt.PublishedStream, PublishedSequence: receipt.PublishedSequence,
	}
	return validateDeploymentStatusAckRecord(ack, record)
}

func validateDurableDeploymentStatusAckReceipt(receipt *durableDeploymentStatusAckReceipt) error {
	if receipt == nil || receipt.Version != deploymentStatusAckReceiptVersion || len(receipt.RecordKey) != sha256.Size*2 ||
		!canonicalUUID(receipt.StatusEventID) || !canonicalUUID(receipt.DeploymentID) || receipt.Attempt == 0 ||
		!safeIdentifier(receipt.ConfigVersionID) || receipt.TransitionSequence == 0 || receipt.PersistedUnixNano <= 0 ||
		timestamppb.New(time.Unix(0, receipt.PersistedUnixNano).UTC()).CheckValid() != nil ||
		(receipt.SessionEpoch == 0) != (receipt.StreamSequence == 0) ||
		(receipt.PublishedStream == "") != (receipt.PublishedSequence == 0) ||
		(receipt.PublishedStream != "" && receipt.PublishedStream != deploymentStatusStream) {
		return fmt.Errorf("%w: deployment acknowledgement receipt is corrupt", ErrInvalidMessage)
	}
	return nil
}

func (c *Client) pendingDeploymentStatusAckReceipts() ([]pendingDeploymentStatusAckReceipt, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	result := make([]pendingDeploymentStatusAckReceipt, 0)
	err := c.store.scanDeploymentStatusAckReceiptsLocked(func(receipt *durableDeploymentStatusAckReceipt) error {
		record, err := c.store.loadLocked(receipt.RecordKey)
		if err != nil {
			return err
		}
		if err := validateDeploymentStatusAckReceiptRecord(receipt, record); err != nil {
			return err
		}
		result = append(result, pendingDeploymentStatusAckReceipt{
			recordKey: receipt.RecordKey, receipt: deploymentStatusAckReceiptProto(receipt),
		})
		return nil
	})
	sort.Slice(result, func(i, j int) bool { return result[i].recordKey < result[j].recordKey })
	return result, err
}

func (s *durableStore) markDeploymentStatusAckReceiptSent(key string, sessionEpoch, streamSequence uint64) error {
	if sessionEpoch == 0 || streamSequence == 0 {
		return fmt.Errorf("%w: invalid deployment acknowledgement receipt send marker", ErrInvalidMessage)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, err := s.loadDeploymentStatusAckReceiptLocked(key)
	if err != nil || receipt == nil {
		return fmt.Errorf("%w: deployment acknowledgement receipt is missing", ErrInvalidMessage)
	}
	record, err := s.loadLocked(key)
	if err != nil {
		return err
	}
	if err := validateDeploymentStatusAckReceiptRecord(receipt, record); err != nil {
		return err
	}
	receipt.SessionEpoch = sessionEpoch
	receipt.StreamSequence = streamSequence
	return s.saveDeploymentStatusAckReceiptLocked(receipt)
}

func (c *Client) confirmDeploymentStatusAckReceipts(sessionEpoch, heartbeatStreamSequence uint64) error {
	if sessionEpoch == 0 || heartbeatStreamSequence == 0 {
		return fmt.Errorf("%w: invalid deployment acknowledgement receipt barrier", ErrInvalidMessage)
	}
	c.store.mu.Lock()
	type confirmation struct {
		ack     *durableDeploymentStatusAck
		receipt *durableDeploymentStatusAckReceipt
	}
	confirmations := make([]confirmation, 0)
	err := c.store.scanDeploymentStatusAckReceiptsLocked(func(receipt *durableDeploymentStatusAckReceipt) error {
		if receipt.SessionEpoch != sessionEpoch || receipt.StreamSequence == 0 || receipt.StreamSequence >= heartbeatStreamSequence {
			return nil
		}
		record, err := c.store.loadLocked(receipt.RecordKey)
		if err != nil {
			return err
		}
		if err := validateDeploymentStatusAckReceiptRecord(receipt, record); err != nil {
			return err
		}
		ack, err := c.store.loadDeploymentStatusAckLocked(receipt.RecordKey)
		if err != nil || ack == nil {
			return fmt.Errorf("%w: deployment acknowledgement is missing", ErrInvalidMessage)
		}
		if err := validateDeploymentStatusAckRecord(ack, record); err != nil {
			return err
		}
		ack.ReceiptConfirmed = true
		confirmations = append(confirmations, confirmation{ack: ack, receipt: receipt})
		return nil
	})
	if err == nil {
		sort.Slice(confirmations, func(i, j int) bool { return confirmations[i].receipt.RecordKey < confirmations[j].receipt.RecordKey })
		for _, confirmation := range confirmations {
			if err = c.store.saveDeploymentStatusAckLocked(confirmation.ack); err != nil {
				break
			}
			if err = removeDurablePath(filepath.Join(c.store.directory, confirmation.receipt.RecordKey+deploymentStatusAckReceiptSuffix)); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = syncDirectory(c.store.directory)
	}
	c.store.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = c.refreshDeploymentHistory()
	return err
}

func validateDeploymentStatusAckRecord(ack *durableDeploymentStatusAck, record *durableRecord) error {
	if ack == nil || ack.Version != deploymentStatusAckVersion || ack.RecordKey == "" || record == nil ||
		ack.RecordKey != record.RecordKey || ack.DeploymentID != record.DeploymentID || ack.Attempt != record.Attempt ||
		ack.ConfigVersionID != record.ConfigVersionID || !record.ExecutionDone ||
		(ack.PublishedStream == "") != (ack.PublishedSequence == 0) ||
		ack.PublishedStream != "" && ack.PublishedStream != deploymentStatusStream {
		return fmt.Errorf("%w: deployment acknowledgement does not match its durable record", ErrInvalidMessage)
	}
	statuses, err := statusesFromRecord(record)
	if err != nil || len(statuses) == 0 {
		return fmt.Errorf("gateway journal status is corrupt")
	}
	final := statuses[len(statuses)-1]
	if !terminalDeploymentState(final.State) || final.Event == nil || final.Event.EventId != ack.StatusEventID ||
		final.TransitionSequence != ack.TransitionSequence || final.DeploymentId != ack.DeploymentID ||
		final.Attempt != ack.Attempt || final.ConfigVersionId != ack.ConfigVersionID {
		return fmt.Errorf("%w: deployment acknowledgement does not match the terminal status", ErrInvalidMessage)
	}
	return nil
}

func legacyDeploymentStatusSentForRecord(record *durableRecord, sessionEpoch, streamSequence uint64) (*durableLegacyDeploymentStatusSent, error) {
	if record == nil || !record.ExecutionDone || sessionEpoch == 0 || streamSequence == 0 {
		return nil, fmt.Errorf("%w: invalid legacy deployment status marker", ErrInvalidMessage)
	}
	statuses, err := statusesFromRecord(record)
	if err != nil || len(statuses) == 0 {
		return nil, fmt.Errorf("gateway journal status is corrupt")
	}
	final := statuses[len(statuses)-1]
	if !terminalDeploymentState(final.State) || final.Event == nil {
		return nil, fmt.Errorf("gateway journal terminal status is corrupt")
	}
	return &durableLegacyDeploymentStatusSent{
		Version: legacyDeploymentStatusSentVersion, RecordKey: record.RecordKey,
		SessionEpoch: sessionEpoch, StreamSequence: streamSequence, StatusEventID: final.Event.EventId,
		DeploymentID: record.DeploymentID, Attempt: record.Attempt, ConfigVersionID: record.ConfigVersionID,
		TransitionSequence: final.TransitionSequence,
	}, nil
}

func validateLegacyDeploymentStatusSentRecord(marker *durableLegacyDeploymentStatusSent, record *durableRecord) error {
	if marker == nil || marker.Version != legacyDeploymentStatusSentVersion || marker.RecordKey == "" ||
		marker.SessionEpoch == 0 || marker.StreamSequence == 0 || record == nil ||
		marker.RecordKey != record.RecordKey || marker.DeploymentID != record.DeploymentID ||
		marker.Attempt != record.Attempt || marker.ConfigVersionID != record.ConfigVersionID || !record.ExecutionDone {
		return fmt.Errorf("%w: legacy deployment status marker does not match its durable record", ErrInvalidMessage)
	}
	statuses, err := statusesFromRecord(record)
	if err != nil || len(statuses) == 0 {
		return fmt.Errorf("gateway journal status is corrupt")
	}
	final := statuses[len(statuses)-1]
	if !terminalDeploymentState(final.State) || final.Event == nil || final.Event.EventId != marker.StatusEventID ||
		final.TransitionSequence != marker.TransitionSequence {
		return fmt.Errorf("%w: legacy deployment status marker does not match the terminal status", ErrInvalidMessage)
	}
	return nil
}

func (s *durableStore) markLegacyDeploymentStatusSent(record *durableRecord, sessionEpoch, streamSequence uint64) error {
	marker, err := legacyDeploymentStatusSentForRecord(record, sessionEpoch, streamSequence)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	persisted, err := s.loadLocked(record.RecordKey)
	if err != nil {
		return err
	}
	if err := validateLegacyDeploymentStatusSentRecord(marker, persisted); err != nil {
		return err
	}
	return s.saveLegacyDeploymentStatusSentLocked(marker)
}

func (s *durableStore) promoteLegacyDeploymentStatuses(sessionEpoch, heartbeatSequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := boundedDeploymentJournalEntriesAt(directory)
	if err != nil {
		return err
	}
	type promotion struct {
		ack        *durableDeploymentStatusAck
		markerPath durablePathSnapshot
		saveAck    bool
	}
	promotions := make([]promotion, 0)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, legacyDeploymentStatusSentSuffix) {
			continue
		}
		key := strings.TrimSuffix(name, legacyDeploymentStatusSentSuffix)
		marker, markerPath, err := loadLegacyDeploymentStatusSentAt(directory, key)
		if err != nil || marker == nil || markerPath.info == nil || !os.SameFile(entry, markerPath.info) {
			return fmt.Errorf("legacy deployment status marker changed during validation")
		}
		record, _, err := s.loadDeploymentRecordAt(directory, key)
		if err != nil {
			return err
		}
		if err := validateLegacyDeploymentStatusSentRecord(marker, record); err != nil {
			return err
		}
		if marker.SessionEpoch != sessionEpoch || marker.StreamSequence >= heartbeatSequence {
			continue
		}
		ack := &durableDeploymentStatusAck{
			Version: deploymentStatusAckVersion, RecordKey: key, StatusEventID: marker.StatusEventID,
			DeploymentID: marker.DeploymentID, Attempt: marker.Attempt, ConfigVersionID: marker.ConfigVersionID,
			TransitionSequence: marker.TransitionSequence,
		}
		existing, _, err := loadDeploymentStatusAckAt(directory, key)
		if err != nil {
			return err
		}
		if existing != nil && *existing != *ack {
			return fmt.Errorf("%w: legacy deployment acknowledgement conflicts with durable state", ErrInvalidMessage)
		}
		promotions = append(promotions, promotion{ack: ack, markerPath: markerPath, saveAck: existing == nil})
	}
	for _, promotion := range promotions {
		if promotion.saveAck {
			if err := s.saveDeploymentStatusAckLocked(promotion.ack); err != nil {
				return err
			}
		}
		if err := removeDurablePathAt(directory, promotion.markerPath); err != nil {
			return err
		}
	}
	return directory.Sync()
}

func (s *durableStore) scanDeploymentRecordsLocked(visit func(*durableRecord) error) error {
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.Readdir(32)
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || filepath.Ext(name) != ".json" || journalSiblingStateFile(name) {
				continue
			}
			key := name[:len(name)-len(".json")]
			if len(key) != sha256.Size*2 {
				return fmt.Errorf("unexpected gateway journal file")
			}
			record, err := s.loadLocked(key)
			if err != nil {
				return err
			}
			if record == nil {
				continue
			}
			if err := visit(record); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (s *durableStore) loadLegacyDeploymentStatusSentLocked(key string) (*durableLegacyDeploymentStatusSent, error) {
	file, err := os.OpenFile(filepath.Join(s.directory, key+legacyDeploymentStatusSentSuffix), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
		return nil, fmt.Errorf("legacy deployment status marker is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	var marker durableLegacyDeploymentStatusSent
	if err := decoder.Decode(&marker); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("decode legacy deployment status marker")
	}
	if marker.Version != legacyDeploymentStatusSentVersion || marker.RecordKey != key || len(key) != sha256.Size*2 ||
		marker.SessionEpoch == 0 || marker.StreamSequence == 0 || !canonicalUUID(marker.StatusEventID) ||
		!canonicalUUID(marker.DeploymentID) || marker.Attempt == 0 || !safeIdentifier(marker.ConfigVersionID) ||
		marker.TransitionSequence == 0 {
		return nil, fmt.Errorf("legacy deployment status marker is corrupt")
	}
	return &marker, nil
}

func (s *durableStore) saveLegacyDeploymentStatusSentLocked(marker *durableLegacyDeploymentStatusSent) error {
	encoded, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.directory, ".deployment-ack-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(s.directory, marker.RecordKey+legacyDeploymentStatusSentSuffix)); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}

func (s *durableStore) loadDeploymentStatusAckLocked(key string) (*durableDeploymentStatusAck, error) {
	file, err := os.OpenFile(filepath.Join(s.directory, key+deploymentStatusAckSuffix), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
		return nil, fmt.Errorf("deployment acknowledgement file is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	var ack durableDeploymentStatusAck
	if err := decoder.Decode(&ack); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("decode deployment acknowledgement")
	}
	if ack.Version != deploymentStatusAckVersion || ack.RecordKey != key || len(key) != sha256.Size*2 ||
		!canonicalUUID(ack.StatusEventID) || !canonicalUUID(ack.DeploymentID) || ack.Attempt == 0 ||
		!safeIdentifier(ack.ConfigVersionID) || ack.TransitionSequence == 0 || ack.PersistedUnixNano < 0 ||
		ack.PersistedUnixNano > 0 && timestamppb.New(time.Unix(0, ack.PersistedUnixNano).UTC()).CheckValid() != nil ||
		(ack.PublishedStream == "") != (ack.PublishedSequence == 0) ||
		ack.PublishedStream != "" && ack.PublishedStream != deploymentStatusStream {
		return nil, fmt.Errorf("deployment acknowledgement file is corrupt")
	}
	return &ack, nil
}

func (s *durableStore) saveDeploymentStatusAckLocked(ack *durableDeploymentStatusAck) error {
	encoded, err := json.Marshal(ack)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.directory, ".deployment-ack-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(s.directory, ack.RecordKey+deploymentStatusAckSuffix)); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}

func (s *durableStore) loadDeploymentStatusAckReceiptLocked(key string) (*durableDeploymentStatusAckReceipt, error) {
	file, err := os.OpenFile(filepath.Join(s.directory, key+deploymentStatusAckReceiptSuffix), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
		return nil, fmt.Errorf("deployment acknowledgement receipt file is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	var receipt durableDeploymentStatusAckReceipt
	if err := decoder.Decode(&receipt); err != nil || decoder.Decode(&struct{}{}) != io.EOF || receipt.RecordKey != key {
		return nil, fmt.Errorf("decode deployment acknowledgement receipt")
	}
	if err := validateDurableDeploymentStatusAckReceipt(&receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

func (s *durableStore) saveDeploymentStatusAckReceiptLocked(receipt *durableDeploymentStatusAckReceipt) error {
	if err := validateDurableDeploymentStatusAckReceipt(receipt); err != nil {
		return err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.directory, ".deployment-ack-receipt-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, filepath.Join(s.directory, receipt.RecordKey+deploymentStatusAckReceiptSuffix)); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}

func (s *durableStore) scanDeploymentStatusAckReceiptsLocked(visit func(*durableDeploymentStatusAckReceipt) error) error {
	directory, err := os.Open(s.directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	for {
		entries, readErr := directory.Readdir(32)
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, deploymentStatusAckReceiptSuffix) {
				continue
			}
			key := strings.TrimSuffix(name, deploymentStatusAckReceiptSuffix)
			receipt, err := s.loadDeploymentStatusAckReceiptLocked(key)
			if err != nil {
				return err
			}
			if err := visit(receipt); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func (s *durableStore) compactAcknowledgedDeploymentRecordsLocked(keep map[string]*durableRecord) error {
	if err := s.scanDeploymentRecordsLocked(func(record *durableRecord) error {
		if record == nil {
			return nil
		}
		ack, err := s.loadDeploymentStatusAckLocked(record.RecordKey)
		if err != nil || ack == nil {
			return err
		}
		if _, retained := keep[record.RecordKey]; retained {
			return nil
		}
		if err := validateDeploymentStatusAckRecord(ack, record); err != nil {
			return err
		}
		intent := deploymentCompactionIntentForAck(ack)
		if err := s.saveDeploymentCompactionIntentLocked(intent); err != nil {
			return err
		}
		return s.finishDeploymentCompactionLocked(intent)
	}); err != nil {
		return err
	}
	if err := s.cleanupDeploymentAckArtifactsLocked(); err != nil {
		return err
	}
	if err := syncDirectory(s.artifacts); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}

func (s *durableStore) cleanupDeploymentAckArtifactsLocked() error {
	return s.cleanupDeploymentAckArtifactsWithHookLocked(nil)
}

func (s *durableStore) cleanupDeploymentAckArtifactsWithHookLocked(beforeMutation func()) error {
	snapshot, err := s.snapshotDeploymentCompactionsLocked()
	if err != nil {
		return err
	}
	defer snapshot.close()
	if err := snapshot.verify(); err != nil {
		return err
	}
	if beforeMutation != nil {
		beforeMutation()
	}
	if err := snapshot.verify(); err != nil {
		return err
	}
	for _, cleanup := range snapshot.cleanup {
		for _, guard := range cleanup.guards {
			if err := verifyDurablePathAt(snapshot.directory, guard); err != nil {
				return err
			}
		}
		if err := removeDurablePathAt(snapshot.directory, cleanup.path); err != nil {
			return err
		}
	}
	return snapshot.directory.Sync()
}

func (s *durableStore) snapshotDeploymentCompactionsLocked() (*deploymentCompactionSnapshot, error) {
	directory, err := os.Open(s.directory)
	if err != nil {
		return nil, err
	}
	artifacts, err := openDurableDirectoryAt(directory, "artifacts")
	if err != nil {
		directory.Close()
		return nil, err
	}
	snapshot := &deploymentCompactionSnapshot{directory: directory, artifacts: artifacts}
	entries, err := boundedDeploymentJournalEntriesAt(directory)
	if err != nil {
		snapshot.close()
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if deploymentCompactionProofName(entry.Name()) {
			snapshot.proofNames = append(snapshot.proofNames, entry.Name())
			proof, err := readDurablePathAt(directory, entry.Name(), 4096)
			if err != nil || proof.info == nil || !os.SameFile(entry, proof.info) {
				snapshot.close()
				return nil, fmt.Errorf("deployment compaction proof is invalid")
			}
			snapshot.proofs = append(snapshot.proofs, proof)
		}
	}
	intentKeys := make(map[string]struct{})
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, deploymentCompactionIntentSuffix) || strings.HasPrefix(name, ".deployment-compaction-") {
			continue
		}
		key := strings.TrimSuffix(name, deploymentCompactionIntentSuffix)
		if len(key) != sha256.Size*2 || !entry.Mode().IsRegular() || entry.Mode().Perm()&0o077 != 0 {
			snapshot.close()
			return nil, fmt.Errorf("deployment compaction intent file is invalid")
		}
		intent, intentPath, err := loadDeploymentCompactionIntentAt(directory, key)
		if err != nil || intent == nil || intentPath.info == nil || !os.SameFile(entry, intentPath.info) {
			snapshot.close()
			return nil, fmt.Errorf("deployment compaction intent is invalid")
		}
		ack, ackPath, err := loadDeploymentStatusAckAt(directory, key)
		if err != nil || ack == nil {
			snapshot.close()
			return nil, fmt.Errorf("deployment compaction intent has no exact durable acknowledgement")
		}
		if expected := deploymentCompactionIntentForAck(ack); *expected != *intent {
			snapshot.close()
			return nil, fmt.Errorf("deployment compaction intent does not match durable acknowledgement")
		}
		record, recordPath, err := s.loadDeploymentRecordAt(directory, key)
		if err != nil {
			snapshot.close()
			return nil, err
		}
		if record != nil {
			if err := validateDeploymentStatusAckRecord(ack, record); err != nil {
				snapshot.close()
				return nil, err
			}
		}
		marker, markerPath, err := loadLegacyDeploymentStatusSentAt(directory, key)
		if err != nil {
			snapshot.close()
			return nil, err
		}
		if marker != nil && (marker.RecordKey != ack.RecordKey || marker.StatusEventID != ack.StatusEventID ||
			marker.DeploymentID != ack.DeploymentID || marker.Attempt != ack.Attempt ||
			marker.ConfigVersionID != ack.ConfigVersionID || marker.TransitionSequence != ack.TransitionSequence) {
			snapshot.close()
			return nil, fmt.Errorf("deployment compaction legacy marker does not match durable acknowledgement")
		}
		artifactPath, err := snapshotDurablePathAt(artifacts, key+".part")
		if err != nil {
			snapshot.close()
			return nil, err
		}
		snapshot.intents = append(snapshot.intents, deploymentCompactionSnapshotEntry{
			intent: intent, ack: ack, intentPath: intentPath, ackPath: ackPath,
			recordPath: recordPath, markerPath: markerPath, artifactPath: artifactPath,
		})
		intentKeys[key] = struct{}{}
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".deployment-ack-") || strings.HasPrefix(name, ".deployment-compaction-") {
			path, err := readDurablePathAt(directory, name, 4096)
			if err != nil || path.info == nil || !os.SameFile(entry, path.info) {
				snapshot.close()
				return nil, fmt.Errorf("deployment acknowledgement temporary is invalid")
			}
			snapshot.cleanup = append(snapshot.cleanup, deploymentCompactionCleanupSnapshot{path: path})
			continue
		}
		if !strings.HasSuffix(name, deploymentStatusAckSuffix) {
			continue
		}
		key := strings.TrimSuffix(name, deploymentStatusAckSuffix)
		if len(key) != sha256.Size*2 || !entry.Mode().IsRegular() || entry.Mode().Perm()&0o077 != 0 {
			snapshot.close()
			return nil, fmt.Errorf("deployment acknowledgement file is invalid")
		}
		if _, live := intentKeys[key]; live {
			continue
		}
		recordGuard, err := snapshotDurablePathAt(directory, key+".json")
		if err != nil {
			snapshot.close()
			return nil, err
		}
		intentGuard, err := snapshotDurablePathAt(directory, key+deploymentCompactionIntentSuffix)
		if err != nil {
			snapshot.close()
			return nil, err
		}
		if recordGuard.info != nil || intentGuard.info != nil {
			continue
		}
		path, err := readDurablePathAt(directory, name, 4096)
		if err != nil || path.info == nil || !os.SameFile(entry, path.info) {
			snapshot.close()
			return nil, fmt.Errorf("deployment acknowledgement file is invalid")
		}
		snapshot.cleanup = append(snapshot.cleanup, deploymentCompactionCleanupSnapshot{
			path: path, guards: []durablePathSnapshot{recordGuard, intentGuard},
		})
	}
	return snapshot, nil
}

func (s *deploymentCompactionSnapshot) close() {
	if s == nil {
		return
	}
	if s.artifacts != nil {
		_ = s.artifacts.Close()
	}
	if s.directory != nil {
		_ = s.directory.Close()
	}
}

func (s *deploymentCompactionSnapshot) verify() error {
	if s == nil || s.directory == nil || s.artifacts == nil {
		return fmt.Errorf("deployment compaction snapshot is invalid")
	}
	proofNames, err := deploymentCompactionProofNamesAt(s.directory)
	if err != nil || len(proofNames) != len(s.proofNames) {
		return fmt.Errorf("deployment compaction proof set changed after validation")
	}
	for position := range proofNames {
		if proofNames[position] != s.proofNames[position] {
			return fmt.Errorf("deployment compaction proof set changed after validation")
		}
	}
	for _, proof := range s.proofs {
		if err := verifyDurablePathAt(s.directory, proof); err != nil {
			return err
		}
	}
	for _, intent := range s.intents {
		for _, path := range []durablePathSnapshot{
			intent.intentPath, intent.ackPath, intent.recordPath, intent.markerPath,
		} {
			if err := verifyDurablePathAt(s.directory, path); err != nil {
				return err
			}
		}
		if err := verifyDurablePathAt(s.artifacts, intent.artifactPath); err != nil {
			return err
		}
	}
	for _, cleanup := range s.cleanup {
		for _, guard := range cleanup.guards {
			if err := verifyDurablePathAt(s.directory, guard); err != nil {
				return err
			}
		}
		if err := verifyDurablePathAt(s.directory, cleanup.path); err != nil {
			return err
		}
	}
	return nil
}

func readDurablePathAt(directory *os.File, name string, maxSize int64) (durablePathSnapshot, error) {
	path := durablePathSnapshot{name: name, maxSize: maxSize}
	file, err := openDurablePathAt(directory, name)
	if err != nil || file == nil {
		return path, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() < 0 || info.Size() > maxSize {
		return path, fmt.Errorf("durable proof file is invalid")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil || int64(len(content)) != info.Size() {
		return path, fmt.Errorf("read durable proof file")
	}
	path.info = info
	path.digest = sha256.Sum256(content)
	path.hasDigest = true
	return path, nil
}

func snapshotDurablePathAt(directory *os.File, name string) (durablePathSnapshot, error) {
	path := durablePathSnapshot{name: name}
	file, err := openDurablePathAt(directory, name)
	if err != nil || file == nil {
		return path, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return path, fmt.Errorf("durable proof path is invalid")
	}
	path.info = info
	return path, nil
}

func openDurablePathAt(directory *os.File, name string) (*os.File, error) {
	if directory == nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, fmt.Errorf("durable proof path is invalid")
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open durable proof path")
	}
	return file, nil
}

func openDurableDirectoryAt(directory *os.File, name string) (*os.File, error) {
	if directory == nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, fmt.Errorf("durable proof directory is invalid")
	}
	fd, err := unix.Openat(
		int(directory.Fd()), name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY,
		0,
	)
	if err != nil {
		return nil, err
	}
	opened := os.NewFile(uintptr(fd), name)
	if opened == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open durable proof directory")
	}
	return opened, nil
}

func deploymentCompactionProofName(name string) bool {
	return strings.HasPrefix(name, ".deployment-ack-") ||
		strings.HasPrefix(name, ".deployment-compaction-") ||
		strings.HasSuffix(name, deploymentStatusAckSuffix) ||
		strings.HasSuffix(name, deploymentStatusAckReceiptSuffix) ||
		strings.HasSuffix(name, deploymentCompactionIntentSuffix)
}

func deploymentCompactionProofNamesAt(directory *os.File) ([]string, error) {
	entries, err := boundedDeploymentJournalEntriesAt(directory)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if deploymentCompactionProofName(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func boundedDeploymentJournalEntriesAt(directory *os.File) ([]os.FileInfo, error) {
	if directory == nil {
		return nil, fmt.Errorf("deployment compaction directory is invalid")
	}
	if _, err := directory.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind deployment compaction directory: %w", err)
	}
	entries := make([]os.FileInfo, 0, deploymentJournalReadBatch)
	var aggregateBytes int64
	for {
		batch, readErr := directory.Readdir(deploymentJournalReadBatch)
		for _, entry := range batch {
			if len(entries) >= deploymentJournalEntryLimit {
				return nil, fmt.Errorf("deployment journal entry budget exceeded")
			}
			if !entry.IsDir() {
				if entry.Size() < 0 || entry.Size() > deploymentJournalAggregateByteLimit-aggregateBytes {
					return nil, fmt.Errorf("deployment journal aggregate byte budget exceeded")
				}
				aggregateBytes += entry.Size()
			}
			entries = append(entries, entry)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func (i deploymentJournalInventory) verify(directory *os.File) error {
	current, err := boundedDeploymentJournalEntriesAt(directory)
	if err != nil || len(current) != len(i.entries) {
		return fmt.Errorf("deployment journal inventory changed after validation")
	}
	for position, expected := range i.entries {
		actual := current[position]
		if expected.Name() != actual.Name() || !os.SameFile(expected, actual) || expected.Mode() != actual.Mode() ||
			expected.Size() != actual.Size() || !expected.ModTime().Equal(actual.ModTime()) {
			return fmt.Errorf("deployment journal inventory changed after validation")
		}
	}
	return nil
}

func verifyDurablePathAt(directory *os.File, expected durablePathSnapshot) error {
	if expected.name == "" {
		return fmt.Errorf("durable proof snapshot is invalid")
	}
	var current durablePathSnapshot
	var err error
	if expected.hasDigest {
		current, err = readDurablePathAt(directory, expected.name, expected.maxSize)
	} else {
		current, err = snapshotDurablePathAt(directory, expected.name)
	}
	if err != nil {
		return err
	}
	if expected.info == nil || current.info == nil {
		if expected.info == nil && current.info == nil {
			return nil
		}
		return fmt.Errorf("durable proof path changed after validation")
	}
	if !os.SameFile(expected.info, current.info) || expected.info.Mode() != current.info.Mode() ||
		expected.info.Size() != current.info.Size() || !expected.info.ModTime().Equal(current.info.ModTime()) ||
		expected.hasDigest && expected.digest != current.digest {
		return fmt.Errorf("durable proof path changed after validation")
	}
	return nil
}

func removeDurablePathAt(directory *os.File, expected durablePathSnapshot) error {
	if err := verifyDurablePathAt(directory, expected); err != nil {
		return err
	}
	if expected.info == nil {
		return nil
	}
	if err := unix.Unlinkat(int(directory.Fd()), expected.name, 0); err != nil {
		return err
	}
	current, err := snapshotDurablePathAt(directory, expected.name)
	if err != nil {
		return err
	}
	if current.info != nil {
		return fmt.Errorf("durable proof path still exists after removal")
	}
	return nil
}

func decodeDurableJSON(content []byte, target any, label string) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return fmt.Errorf("decode %s", label)
	}
	return nil
}

func loadDeploymentCompactionIntentAt(
	directory *os.File,
	key string,
) (*durableDeploymentCompactionIntent, durablePathSnapshot, error) {
	path, err := readDurablePathAt(directory, key+deploymentCompactionIntentSuffix, 4096)
	if err != nil || path.info == nil {
		return nil, path, err
	}
	content, err := readDurablePathContentAt(directory, path)
	if err != nil {
		return nil, path, err
	}
	var intent durableDeploymentCompactionIntent
	if err := decodeDurableJSON(content, &intent, "deployment compaction intent"); err != nil || intent.RecordKey != key {
		return nil, path, fmt.Errorf("decode deployment compaction intent")
	}
	if err := validateDeploymentCompactionIntent(&intent); err != nil {
		return nil, path, err
	}
	return &intent, path, nil
}

func loadDeploymentStatusAckAt(
	directory *os.File,
	key string,
) (*durableDeploymentStatusAck, durablePathSnapshot, error) {
	path, err := readDurablePathAt(directory, key+deploymentStatusAckSuffix, 4096)
	if err != nil || path.info == nil {
		return nil, path, err
	}
	content, err := readDurablePathContentAt(directory, path)
	if err != nil {
		return nil, path, err
	}
	var ack durableDeploymentStatusAck
	if err := decodeDurableJSON(content, &ack, "deployment acknowledgement"); err != nil {
		return nil, path, err
	}
	if ack.Version != deploymentStatusAckVersion || ack.RecordKey != key || len(key) != sha256.Size*2 ||
		!canonicalUUID(ack.StatusEventID) || !canonicalUUID(ack.DeploymentID) || ack.Attempt == 0 ||
		!safeIdentifier(ack.ConfigVersionID) || ack.TransitionSequence == 0 || ack.PersistedUnixNano < 0 ||
		ack.PersistedUnixNano > 0 && timestamppb.New(time.Unix(0, ack.PersistedUnixNano).UTC()).CheckValid() != nil {
		return nil, path, fmt.Errorf("deployment acknowledgement file is corrupt")
	}
	return &ack, path, nil
}

func loadDeploymentStatusAckReceiptAt(
	directory *os.File,
	key string,
) (*durableDeploymentStatusAckReceipt, durablePathSnapshot, error) {
	path, err := readDurablePathAt(directory, key+deploymentStatusAckReceiptSuffix, 4096)
	if err != nil || path.info == nil {
		return nil, path, err
	}
	content, err := readDurablePathContentAt(directory, path)
	if err != nil {
		return nil, path, err
	}
	var receipt durableDeploymentStatusAckReceipt
	if err := decodeDurableJSON(content, &receipt, "deployment acknowledgement receipt"); err != nil || receipt.RecordKey != key {
		return nil, path, fmt.Errorf("decode deployment acknowledgement receipt")
	}
	if err := validateDurableDeploymentStatusAckReceipt(&receipt); err != nil {
		return nil, path, err
	}
	canonical, err := json.Marshal(&receipt)
	if err != nil || path.digest != sha256.Sum256(canonical) {
		return nil, path, fmt.Errorf("deployment acknowledgement receipt file is noncanonical")
	}
	return &receipt, path, nil
}

func (s *durableStore) loadDeploymentRecordAt(
	directory *os.File,
	key string,
) (*durableRecord, durablePathSnapshot, error) {
	maxSize := int64(2*s.maxCommandBytes + 8*s.maxStatusBytes)
	path, err := readDurablePathAt(directory, key+".json", maxSize)
	if err != nil || path.info == nil {
		return nil, path, err
	}
	content, err := readDurablePathContentAt(directory, path)
	if err != nil {
		return nil, path, err
	}
	var record durableRecord
	if err := decodeDurableJSON(content, &record, "gateway journal"); err != nil {
		return nil, path, err
	}
	if err := s.validateRecord(&record, key); err != nil {
		return nil, path, err
	}
	return &record, path, nil
}

func loadLegacyDeploymentStatusSentAt(
	directory *os.File,
	key string,
) (*durableLegacyDeploymentStatusSent, durablePathSnapshot, error) {
	path, err := readDurablePathAt(directory, key+legacyDeploymentStatusSentSuffix, 4096)
	if err != nil || path.info == nil {
		return nil, path, err
	}
	content, err := readDurablePathContentAt(directory, path)
	if err != nil {
		return nil, path, err
	}
	var marker durableLegacyDeploymentStatusSent
	if err := decodeDurableJSON(content, &marker, "legacy deployment status marker"); err != nil {
		return nil, path, err
	}
	if marker.Version != legacyDeploymentStatusSentVersion || marker.RecordKey != key || len(key) != sha256.Size*2 ||
		marker.SessionEpoch == 0 || marker.StreamSequence == 0 || !canonicalUUID(marker.StatusEventID) ||
		!canonicalUUID(marker.DeploymentID) || marker.Attempt == 0 || !safeIdentifier(marker.ConfigVersionID) ||
		marker.TransitionSequence == 0 {
		return nil, path, fmt.Errorf("legacy deployment status marker is corrupt")
	}
	return &marker, path, nil
}

func readDurablePathContentAt(directory *os.File, expected durablePathSnapshot) ([]byte, error) {
	file, err := openDurablePathAt(directory, expected.name)
	if err != nil || file == nil {
		return nil, fmt.Errorf("durable proof path changed after validation")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(expected.info, info) || info.Size() < 0 || info.Size() > expected.maxSize {
		return nil, fmt.Errorf("durable proof path changed after validation")
	}
	content, err := io.ReadAll(io.LimitReader(file, expected.maxSize+1))
	if err != nil || int64(len(content)) != info.Size() || sha256.Sum256(content) != expected.digest {
		return nil, fmt.Errorf("durable proof path changed after validation")
	}
	return content, nil
}

func deploymentCompactionIntentForAck(ack *durableDeploymentStatusAck) *durableDeploymentCompactionIntent {
	if ack == nil {
		return nil
	}
	return &durableDeploymentCompactionIntent{
		Version: deploymentCompactionIntentVersion, RecordKey: ack.RecordKey, StatusEventID: ack.StatusEventID,
		DeploymentID: ack.DeploymentID, Attempt: ack.Attempt, ConfigVersionID: ack.ConfigVersionID,
		TransitionSequence: ack.TransitionSequence,
	}
}

func validateDeploymentCompactionIntent(intent *durableDeploymentCompactionIntent) error {
	if intent == nil || intent.Version != deploymentCompactionIntentVersion || len(intent.RecordKey) != sha256.Size*2 ||
		!canonicalUUID(intent.StatusEventID) || !canonicalUUID(intent.DeploymentID) || intent.Attempt == 0 ||
		!safeIdentifier(intent.ConfigVersionID) || intent.TransitionSequence == 0 {
		return fmt.Errorf("deployment compaction intent is corrupt")
	}
	return nil
}

func (s *durableStore) saveDeploymentCompactionIntentLocked(intent *durableDeploymentCompactionIntent) error {
	if err := validateDeploymentCompactionIntent(intent); err != nil {
		return err
	}
	encoded, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.directory, ".deployment-compaction-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	path := filepath.Join(s.directory, intent.RecordKey+deploymentCompactionIntentSuffix)
	if existing, err := s.loadDeploymentCompactionIntentLocked(intent.RecordKey); err != nil {
		return err
	} else if existing != nil && *existing != *intent {
		return fmt.Errorf("deployment compaction intent conflicts with durable state")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}

func (s *durableStore) loadDeploymentCompactionIntentLocked(key string) (*durableDeploymentCompactionIntent, error) {
	file, err := os.OpenFile(filepath.Join(s.directory, key+deploymentCompactionIntentSuffix), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 4096 {
		return nil, fmt.Errorf("deployment compaction intent is invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(file, info.Size()+1))
	decoder.DisallowUnknownFields()
	var intent durableDeploymentCompactionIntent
	if err := decoder.Decode(&intent); err != nil || decoder.Decode(&struct{}{}) != io.EOF || intent.RecordKey != key {
		return nil, fmt.Errorf("decode deployment compaction intent")
	}
	if err := validateDeploymentCompactionIntent(&intent); err != nil {
		return nil, err
	}
	return &intent, nil
}

func (s *durableStore) recoverDeploymentCompactionsLocked() error {
	snapshot, err := s.snapshotDeploymentCompactionsLocked()
	if err != nil {
		return err
	}
	defer snapshot.close()
	if err := snapshot.verify(); err != nil {
		return err
	}
	for _, intent := range snapshot.intents {
		if err := finishDeploymentCompactionAt(snapshot, intent); err != nil {
			return err
		}
	}
	return nil
}

func (s *durableStore) finishDeploymentCompactionLocked(intent *durableDeploymentCompactionIntent) error {
	if err := validateDeploymentCompactionIntent(intent); err != nil {
		return err
	}
	snapshot, err := s.snapshotDeploymentCompactionsLocked()
	if err != nil {
		return err
	}
	defer snapshot.close()
	if err := snapshot.verify(); err != nil {
		return err
	}
	for _, candidate := range snapshot.intents {
		if *candidate.intent == *intent {
			return finishDeploymentCompactionAt(snapshot, candidate)
		}
	}
	return fmt.Errorf("deployment compaction intent is not durable")
}

func finishDeploymentCompactionAt(
	snapshot *deploymentCompactionSnapshot,
	intent deploymentCompactionSnapshotEntry,
) error {
	if snapshot == nil || intent.intent == nil || intent.ack == nil ||
		*deploymentCompactionIntentForAck(intent.ack) != *intent.intent {
		return fmt.Errorf("deployment compaction snapshot is invalid")
	}
	if err := removeDurablePathAt(snapshot.directory, intent.markerPath); err != nil {
		return err
	}
	if err := snapshot.directory.Sync(); err != nil {
		return err
	}
	if err := removeDurablePathAt(snapshot.artifacts, intent.artifactPath); err != nil {
		return err
	}
	if err := snapshot.artifacts.Sync(); err != nil {
		return err
	}
	if err := removeDurablePathAt(snapshot.directory, intent.recordPath); err != nil {
		return err
	}
	if err := snapshot.directory.Sync(); err != nil {
		return err
	}
	if err := removeDurablePathAt(snapshot.directory, intent.intentPath); err != nil {
		return err
	}
	if err := snapshot.directory.Sync(); err != nil {
		return err
	}
	if err := removeDurablePathAt(snapshot.directory, intent.ackPath); err != nil {
		return err
	}
	return snapshot.directory.Sync()
}

func removeDurablePath(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func sortDeploymentRecords(records []*durableRecord) {
	sort.Slice(records, func(i, j int) bool {
		if records[i].DeploymentID == records[j].DeploymentID {
			return records[i].Attempt < records[j].Attempt
		}
		return records[i].DeploymentID < records[j].DeploymentID
	})
}

func (c *Client) completeDeploymentRecord(key string, statuses []*agentv1.DeploymentStatus, activeIdentityEnabled bool) error {
	if activeIdentityEnabled && len(statuses) > 0 && terminalDeploymentState(statuses[len(statuses)-1].State) {
		final := statuses[len(statuses)-1]
		final.ActiveConfigIdentityCapability = activeConfigIdentityCapability()
		final.ActiveConfigIdentity = nil
		if final.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY ||
			final.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
			record, err := c.store.record(key)
			if err != nil {
				return err
			}
			command := commandFromBytes(record.Command)
			pointers, err := c.commandPointers(command)
			if err != nil {
				return err
			}
			if final.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
				command != nil && command.ConfigVersionId == pointers.Current && configurationDescriptor(command) != nil {
				final.ActiveConfigIdentity = c.verifiedActiveConfigIdentity(record, command, configurationDescriptor(command), pointers.CurrentDigest, final)
			}
			if final.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED && command != nil &&
				command.Action == agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK && command.ConfigVersionId == pointers.Current {
				_, history, err := c.stableActiveConfigSnapshot()
				if err != nil {
					return err
				}
				stablePointers, err := c.commandPointers(command)
				if err != nil {
					return err
				}
				if !sameDeploymentPointers(stablePointers, pointers) {
					return fmt.Errorf("active config pointers changed while completing rollback")
				}
				final.ActiveConfigIdentity = c.activeConfigIdentity(pointers.Current, pointers.CurrentDigest, history.records)
				if final.ActiveConfigIdentity == nil {
					return fmt.Errorf("reverted deployment active config identity is unavailable")
				}
			}
		}
	}
	return c.store.appendStatuses(key, statuses, true)
}

func deploymentStatusForSession(status *agentv1.DeploymentStatus, activeIdentityEnabled bool) *agentv1.DeploymentStatus {
	copyStatus := proto.Clone(status).(*agentv1.DeploymentStatus)
	if !activeIdentityEnabled {
		copyStatus.ActiveConfigIdentityCapability = nil
		copyStatus.ActiveConfigIdentity = nil
		return copyStatus
	}
	if copyStatus.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY &&
		copyStatus.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
		copyStatus.ActiveConfigIdentity = nil
	}
	return copyStatus
}

func terminalDeploymentState(state agentv1.NodeDeploymentState) bool {
	switch state {
	case agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_SUPERSEDED:
		return true
	default:
		return false
	}
}

func cloneActiveConfigIdentity(identity *agentv1.ActiveConfigIdentity) *agentv1.ActiveConfigIdentity {
	if identity == nil {
		return nil
	}
	return proto.Clone(identity).(*agentv1.ActiveConfigIdentity)
}
