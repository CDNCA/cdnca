package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderlive"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

func runAll(ctx context.Context, batch *preparedBatch, writer evidenceWriter, evidence batchEvidence) batchEvidence {
	runID, ok := randomRunID()
	if !ok {
		evidence.Status, evidence.Reason = "fail", "entropy_unavailable"
		return evidence
	}
	for index := range batch.providers {
		if !runProvider(ctx, batch.providers[index], runID, index, writer, &evidence) {
			evidence.Status = "fail"
			if evidence.Reason == "running" {
				evidence.Reason = evidence.Providers[index].Reason
			}
			return evidence
		}
	}
	evidence.Status, evidence.Reason = "pass", "verified"
	return evidence
}

func runProvider(
	parent context.Context,
	prepared preparedProvider,
	runID string,
	index int,
	writer evidenceWriter,
	evidence *batchEvidence,
) bool {
	providerEvidence := &evidence.Providers[index]
	providerEvidence.Status, providerEvidence.Reason = "running", "running"
	if writer.write(*evidence) != nil {
		providerEvidence.Status, providerEvidence.Reason = "fail", "evidence_write_failed"
		evidence.Reason = providerEvidence.Reason
		return false
	}

	ctx, cancel := context.WithTimeout(parent, time.Duration(prepared.input.TimeoutSeconds)*time.Second)
	defer cancel()
	tenantID, scopeID, providerID, zoneID, _, ok := randomAuthority()
	if !ok {
		return finishProviderFailure(evidence, index, writer, "entropy_unavailable")
	}
	source := &sandboxSource{
		tenantID: tenantID, scopeID: scopeID, providerID: providerID, zoneID: zoneID,
		providerType: prepared.input.Code, zone: prepared.input.Zone, credentials: prepared.lease.Values,
	}

	txtResourceIndex := len(evidence.Resources)
	evidence.Resources = append(evidence.Resources, resourceEvidence{
		Provider: prepared.input.Code, Kind: "txt_lifecycle",
		IdentitySHA256: identityDigest(prepared.input.Code, "txt_lifecycle", runID), State: "planned",
	})
	appendPendingStep(providerEvidence, "txt_lifecycle", stableProviderRequestID(runID, prepared.input.Code, "txt_lifecycle"), 1)
	if writer.write(*evidence) != nil {
		return finishProviderFailure(evidence, index, writer, "evidence_write_failed")
	}
	txtComplete := runTXTLifecycle(ctx, prepared, source)
	finishPendingStep(providerEvidence, txtComplete, passFailReason(txtComplete, "txt_lifecycle_failed"), false)
	providerEvidence.Steps[len(providerEvidence.Steps)-1].AuthoritativeConverged = txtComplete
	providerEvidence.Steps[len(providerEvidence.Steps)-1].PublicConverged = txtComplete
	providerEvidence.CleanupAttempted = true
	providerEvidence.CleanupComplete = txtComplete
	providerEvidence.AuthoritativeConverged = txtComplete
	providerEvidence.PublicRecursiveConverged = txtComplete
	evidence.Resources[txtResourceIndex].Revision = 1
	evidence.Resources[txtResourceIndex].State = ternary(txtComplete, "absent", "cleanup_pending")
	if writer.write(*evidence) != nil {
		return finishProviderFailure(evidence, index, writer, "evidence_write_failed")
	}
	if !txtComplete {
		return finishProviderFailure(evidence, index, writer, "txt_lifecycle_failed")
	}

	owner := "cdnca-sbx-" + runID[:20] + "." + prepared.input.Zone + "."
	lookup := dnsproviderremote.ProviderLookup{
		TenantID: tenantID, ScopeID: scopeID, TenantScopeID: scopeID,
		ProviderID: providerID, ZoneID: zoneID, OwnerName: owner,
	}
	config, err := source.Resolve(ctx, lookup)
	if err != nil {
		return finishProviderFailure(evidence, index, writer, "source_unavailable")
	}
	defer clearConfigCredentials(&config)
	remote := dnsproviderremote.NewReconcileRemote()
	records := []recordLifecycleSpec{
		{Kind: "a_record", Type: dnscheck.RecordA, Initial: prepared.input.InitialIPv4, Updated: prepared.input.UpdatedIPv4, ProbeRateLimit: true},
		{Kind: "aaaa_record", Type: dnscheck.RecordAAAA, Initial: prepared.input.InitialIPv6, Updated: prepared.input.UpdatedIPv6},
		{Kind: "cname_record", Type: dnscheck.RecordCNAME, Initial: prepared.input.CNAMETarget, Updated: prepared.input.UpdatedCNAMETarget},
	}
	for _, record := range records {
		owner := "cdnca-sbx-" + strings.TrimSuffix(record.Kind, "_record") + "-" + runID[:16] + "." + prepared.input.Zone + "."
		if !runRecordLifecycle(ctx, prepared, remote, config, record, owner, runID, index, writer, evidence, waitForRecordState, record.ProbeRateLimit) {
			return false
		}
	}

	providerEvidence.Status, providerEvidence.Reason = "pass", "verified"
	if writer.write(*evidence) != nil {
		providerEvidence.Status, providerEvidence.Reason = "fail", "evidence_write_failed"
		evidence.Reason = providerEvidence.Reason
		return false
	}
	return true
}

type recordLifecycleSpec struct {
	Kind           string
	Type           dnscheck.RecordType
	Initial        string
	Updated        string
	ProbeRateLimit bool
}

type recordStateWaiter func(context.Context, preparedProvider, string, dnscheck.RecordType, string, bool) (bool, bool)

func runRecordLifecycle(
	ctx context.Context,
	prepared preparedProvider,
	remote dnsproviderremote.ReconcileRemote,
	config dnsproviderremote.ProviderConfig,
	spec recordLifecycleSpec,
	owner, runID string,
	providerIndex int,
	writer evidenceWriter,
	evidence *batchEvidence,
	waiter recordStateWaiter,
	probeRateLimit bool,
) bool {
	provider := &evidence.Providers[providerIndex]
	stepPrefix := strings.TrimSuffix(spec.Kind, "_record")
	resourceIndex := len(evidence.Resources)
	evidence.Resources = append(evidence.Resources, resourceEvidence{
		Provider: prepared.input.Code, Kind: spec.Kind,
		IdentitySHA256: identityDigest(prepared.input.Code, spec.Kind, owner), State: "planned",
	})
	create := dnscheck.ProviderOperation{
		Sequence: 1, Action: dnscheck.ProviderCreate, Name: owner, Type: spec.Type,
		Value: spec.Initial, TTL: prepared.input.TTL, Reason: "sandbox_create",
	}
	initial, err := remote.Lookup(ctx, config, create)
	if err != nil || initial.TargetComplete || initial.Conflict || initial.Ambiguous {
		evidence.Resources[resourceIndex].State = "absent"
		_ = writer.write(*evidence)
		return finishProviderFailure(evidence, providerIndex, writer, stableRemoteReason(err, "create_precondition_failed"))
	}
	appendPendingStep(provider, stepPrefix+"_create", stableProviderRequestID(runID, prepared.input.Code, stepPrefix+"_create"), 1)
	if writer.write(*evidence) != nil {
		return finishProviderFailure(evidence, providerIndex, writer, "evidence_write_failed")
	}
	recordID, createOK, recovered, mutationReason := mutateWithExactRecovery(ctx, remote, config, create)
	finishPendingStep(provider, createOK, mutationReason, recovered)
	if !createOK {
		evidence.Resources[resourceIndex].State = "cleanup_pending"
		_ = writer.write(*evidence)
		return finishProviderFailure(evidence, providerIndex, writer, provider.Steps[len(provider.Steps)-1].Reason)
	}
	create.RecordID = recordID
	setResourceIdentity(&evidence.Resources[resourceIndex], recordID, 1, "present")
	if writer.write(*evidence) != nil {
		return cleanupRecordAndFail(ctx, prepared, remote, config, create, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, "evidence_write_failed")
	}

	readback, err := remote.Lookup(ctx, config, create)
	readOK := exactPresent(readback, err, recordID)
	appendStep(provider, stepPrefix+"_read", readOK, stableRemoteReason(err, "readback_failed"), stableProviderRequestID(runID, prepared.input.Code, stepPrefix+"_read"), 0)
	if writer.write(*evidence) != nil || !readOK {
		return cleanupRecordAndFail(ctx, prepared, remote, config, create, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, provider.Steps[len(provider.Steps)-1].Reason)
	}

	update := dnscheck.ProviderOperation{
		Sequence: 2, Action: dnscheck.ProviderUpdate, RecordID: recordID,
		Name: owner, Type: spec.Type, Value: spec.Updated,
		TTL: prepared.input.UpdatedTTL, Line: prepared.input.UpdateLine, Weight: prepared.input.UpdateWeight,
		PreviousValue: spec.Initial, PreviousTTL: prepared.input.TTL,
		Reason: "sandbox_update",
	}
	appendPendingStep(provider, stepPrefix+"_update", stableProviderRequestID(runID, prepared.input.Code, stepPrefix+"_update"), 2)
	if writer.write(*evidence) != nil {
		return cleanupRecordAndFail(ctx, prepared, remote, config, create, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, "evidence_write_failed")
	}
	updatedRecordID, updateOK, recovered, mutationReason := mutateWithExactRecovery(ctx, remote, config, update)
	finishPendingStep(provider, updateOK, mutationReason, recovered)
	if updatedRecordID != "" {
		recordID = updatedRecordID
		update.RecordID = updatedRecordID
	}
	if !updateOK {
		_ = writer.write(*evidence)
		return cleanupRecordAndFail(ctx, prepared, remote, config, update, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, provider.Steps[len(provider.Steps)-1].Reason)
	}
	setResourceIdentity(&evidence.Resources[resourceIndex], recordID, 2, "present")
	if writer.write(*evidence) != nil {
		return cleanupRecordAndFail(ctx, prepared, remote, config, update, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, "evidence_write_failed")
	}

	updatedLookup, err := remote.Lookup(ctx, config, update)
	updatedReadOK := exactPresent(updatedLookup, err, recordID)
	appendStep(provider, stepPrefix+"_updated_read", updatedReadOK, stableRemoteReason(err, "updated_read_failed"), stableProviderRequestID(runID, prepared.input.Code, stepPrefix+"_updated_read"), 0)
	if writer.write(*evidence) != nil || !updatedReadOK {
		return cleanupRecordAndFail(ctx, prepared, remote, config, update, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, provider.Steps[len(provider.Steps)-1].Reason)
	}

	authoritative, public := waiter(ctx, prepared, owner, spec.Type, spec.Updated, true)
	provider.AuthoritativeConverged = provider.AuthoritativeConverged && authoritative
	provider.PublicRecursiveConverged = provider.PublicRecursiveConverged && public
	provider.Steps[len(provider.Steps)-1].AuthoritativeConverged = authoritative
	provider.Steps[len(provider.Steps)-1].PublicConverged = public
	if writer.write(*evidence) != nil || !authoritative || !public {
		return cleanupRecordAndFail(ctx, prepared, remote, config, update, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, "dns_convergence_failed")
	}

	if probeRateLimit {
		retryAfter, rateReason := observeRateLimit(ctx, prepared, remote, config, update)
		rateOK := retryAfter > 0
		appendStep(provider, "rate_limit", rateOK, rateReason, stableProviderRequestID(runID, prepared.input.Code, "rate_limit"), int64(retryAfter/time.Second))
		if writer.write(*evidence) != nil || !rateOK {
			return cleanupRecordAndFail(ctx, prepared, remote, config, update, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, provider.Steps[len(provider.Steps)-1].Reason)
		}
		if !sleepContext(ctx, retryAfter) {
			return cleanupRecordAndFail(ctx, prepared, remote, config, update, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, "retry_after_wait_failed")
		}
	}

	deleteOperation := currentDeleteOperation(update, recordID)
	appendPendingStep(provider, stepPrefix+"_delete", stableProviderRequestID(runID, prepared.input.Code, stepPrefix+"_delete"), 3)
	if writer.write(*evidence) != nil {
		return finishProviderFailure(evidence, providerIndex, writer, "evidence_write_failed")
	}
	_, deleteOK, recovered, mutationReason := mutateWithExactRecovery(ctx, remote, config, deleteOperation)
	finishPendingStep(provider, deleteOK, mutationReason, recovered)
	provider.CleanupAttempted = true
	if !deleteOK {
		_ = writer.write(*evidence)
		return cleanupRecordAndFail(ctx, prepared, remote, config, update, spec, owner, recordID, runID, resourceIndex, providerIndex, writer, evidence, waiter, provider.Steps[len(provider.Steps)-1].Reason)
	}

	absence, err := remote.Lookup(ctx, config, deleteOperation)
	readbackOK := exactAbsent(absence, err, recordID)
	authoritative, public = waiter(ctx, prepared, owner, spec.Type, spec.Updated, false)
	readbackOK = readbackOK && authoritative && public
	appendStep(provider, stepPrefix+"_absence", readbackOK, stableRemoteReason(err, "dns_absence_failed"), stableProviderRequestID(runID, prepared.input.Code, stepPrefix+"_absence"), 0)
	provider.Steps[len(provider.Steps)-1].AuthoritativeConverged = authoritative
	provider.Steps[len(provider.Steps)-1].PublicConverged = public
	provider.CleanupComplete = provider.CleanupComplete && readbackOK
	setResourceIdentity(&evidence.Resources[resourceIndex], recordID, 3, ternary(readbackOK, "absent", "cleanup_pending"))
	if writer.write(*evidence) != nil || !readbackOK {
		return finishProviderFailure(evidence, providerIndex, writer, provider.Steps[len(provider.Steps)-1].Reason)
	}
	return true
}

func runTXTLifecycle(ctx context.Context, prepared preparedProvider, source *sandboxSource) bool {
	secret := make([]byte, sha256.Size)
	if _, err := rand.Read(secret); err != nil {
		clear(secret)
		return false
	}
	keyring, err := dnsproviderremote.NewHandleKeyring(dnsproviderremote.HandleKey{ID: "sandbox-v1", Secret: secret})
	clear(secret)
	if err != nil {
		return false
	}
	provider, err := dnsproviderremote.Open(ctx, source, keyring)
	if err != nil {
		return false
	}
	evidence := dnsproviderlive.Run(ctx, dnsproviderlive.Config{
		ProviderCode: prepared.input.Code, Zone: prepared.input.Zone,
		GuardOwner: prepared.input.GuardOwner, GuardSHA256: prepared.guard,
		Authoritative: prepared.authority, Public: prepared.public,
		Timeout:        time.Duration(prepared.input.TimeoutSeconds) * time.Second,
		CleanupTimeout: time.Duration(prepared.input.CleanupTimeoutSeconds) * time.Second,
		TenantID:       source.tenantID, ScopeID: source.scopeID,
		ProviderID: source.providerID, ZoneID: source.zoneID,
	}, provider, dnsproviderlive.NewWireDNS(), wallClock{}, rand.Reader)
	return evidence.Status == dnsproviderlive.StatusPass && evidence.CleanupAttempted && evidence.CleanupComplete
}

func observeRateLimit(
	ctx context.Context,
	prepared preparedProvider,
	remote dnsproviderremote.ReconcileRemote,
	config dnsproviderremote.ProviderConfig,
	operation dnscheck.ProviderOperation,
) (time.Duration, string) {
	interval := time.Duration(prepared.input.RateLimitIntervalMS) * time.Millisecond
	for attempt := 0; attempt < prepared.input.RateLimitMaximumReads; attempt++ {
		_, err := remote.Lookup(ctx, config, operation)
		if err != nil {
			var providerError *dnsproviderremote.Error
			if errors.As(err, &providerError) && providerError.Code == dnsproviderremote.CodeRateLimited &&
				providerError.RetryAfter > 0 && providerError.RetryAfter <= time.Hour {
				return providerError.RetryAfter, "verified"
			}
			return 0, stableRemoteReason(err, "rate_limit_probe_failed")
		}
		if attempt+1 < prepared.input.RateLimitMaximumReads && !sleepContext(ctx, interval) {
			return 0, "rate_limit_probe_cancelled"
		}
	}
	return 0, "rate_limit_not_observed"
}

func waitForRecordState(
	ctx context.Context,
	prepared preparedProvider,
	owner string,
	recordType dnscheck.RecordType,
	value string,
	present bool,
) (bool, bool) {
	endpoints := append(append([]dnsproviderlive.Endpoint(nil), prepared.authority...), prepared.public...)
	resolverEndpoints := make([]dnscheck.ResolverEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		resolved, err := dnscheck.NewResolverEndpoint("udp", endpoint.Address.Addr().String(), endpoint.Address.Port())
		if err != nil {
			return false, false
		}
		resolverEndpoints = append(resolverEndpoints, resolved)
	}
	policy, err := dnscheck.NewEndpointPolicy(resolverEndpoints...)
	if err != nil {
		return false, false
	}
	resolver, err := dnscheck.NewNetworkResolver(policy, dnscheck.NetworkResolverOptions{})
	if err != nil {
		return false, false
	}
	return waitForRecordStateWithEndpoints(ctx, prepared, resolver, resolverEndpoints, owner, recordType, value, present)
}

func waitForRecordStateWithResolver(
	ctx context.Context,
	prepared preparedProvider,
	resolver dnscheck.Resolver,
	owner string,
	recordType dnscheck.RecordType,
	value string,
	present bool,
) (bool, bool) {
	endpoints := append(append([]dnsproviderlive.Endpoint(nil), prepared.authority...), prepared.public...)
	resolverEndpoints := make([]dnscheck.ResolverEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		resolved, err := dnscheck.NewResolverEndpoint("udp", endpoint.Address.Addr().String(), endpoint.Address.Port())
		if err != nil {
			return false, false
		}
		resolverEndpoints = append(resolverEndpoints, resolved)
	}
	return waitForRecordStateWithEndpoints(ctx, prepared, resolver, resolverEndpoints, owner, recordType, value, present)
}

func waitForRecordStateWithEndpoints(
	ctx context.Context,
	prepared preparedProvider,
	resolver dnscheck.Resolver,
	endpoints []dnscheck.ResolverEndpoint,
	owner string,
	recordType dnscheck.RecordType,
	value string,
	present bool,
) (bool, bool) {
	authorityEndpoints := endpoints[:len(prepared.authority)]
	publicEndpoints := endpoints[len(prepared.authority):]
	if !waitForEndpointGroup(ctx, resolver, authorityEndpoints, owner, recordType, value, present, true) {
		return false, false
	}
	return true, waitForEndpointGroup(ctx, resolver, publicEndpoints, owner, recordType, value, present, false)
}

func waitForEndpointGroup(
	ctx context.Context,
	resolver dnscheck.Resolver,
	endpoints []dnscheck.ResolverEndpoint,
	owner string,
	recordType dnscheck.RecordType,
	value string,
	present, authoritative bool,
) bool {
	for attempt := 0; ; attempt++ {
		if endpointsMatchRecord(ctx, resolver, endpoints, owner, recordType, value, present, authoritative) {
			return true
		}
		if !sleepContext(ctx, boundedBackoff(attempt)) {
			return false
		}
	}
}

func endpointsMatchRecord(
	ctx context.Context,
	resolver dnscheck.Resolver,
	endpoints []dnscheck.ResolverEndpoint,
	owner string,
	recordType dnscheck.RecordType,
	value string,
	present, authoritative bool,
) bool {
	for _, endpoint := range endpoints {
		queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		response, err := resolver.Resolve(queryCtx, endpoint, dnscheck.DNSQuery{Name: owner, Type: recordType})
		cancel()
		if err != nil || response.Authoritative != authoritative {
			return false
		}
		matches := 0
		for _, answer := range response.Answers {
			if answer.Type == recordType && strings.EqualFold(strings.TrimSuffix(answer.Name, "."), strings.TrimSuffix(owner, ".")) {
				if !recordValueEqual(recordType, answer.Value, value) {
					return false
				}
				matches++
			}
		}
		if present && (response.RCode != 0 || matches != 1) ||
			!present && (matches != 0 || response.RCode != 0 && response.RCode != 3) {
			return false
		}
	}
	return true
}

func recordValueEqual(recordType dnscheck.RecordType, observed, expected string) bool {
	if recordType == dnscheck.RecordCNAME {
		return strings.EqualFold(strings.TrimSuffix(observed, "."), strings.TrimSuffix(expected, "."))
	}
	return observed == expected
}

func mutateWithExactRecovery(
	ctx context.Context,
	remote dnsproviderremote.ReconcileRemote,
	config dnsproviderremote.ProviderConfig,
	operation dnscheck.ProviderOperation,
) (string, bool, bool, string) {
	recordID, err := remote.Mutate(ctx, config, operation)
	if err == nil && (operation.Action == dnscheck.ProviderDelete || recordID != "") {
		return recordID, true, false, "verified"
	}
	reason := stableRemoteReason(err, string(operation.Action)+"_failed")
	recovered, lookupErr := remote.Lookup(ctx, config, operation)
	if lookupErr != nil || recovered.Conflict || recovered.Ambiguous || !recovered.TargetComplete {
		return recordID, false, false, reason
	}
	if operation.Action == dnscheck.ProviderDelete && recovered.RecordID == operation.RecordID {
		return "", true, true, "unknown_outcome_recovered"
	}
	if recovered.RecordID == "" {
		return recordID, false, false, reason
	}
	return recovered.RecordID, true, true, "unknown_outcome_recovered"
}

func exactPresent(result dnsproviderremote.ReconcileLookup, err error, recordID string) bool {
	return err == nil && result.TargetComplete && !result.Conflict && !result.Ambiguous &&
		result.RecordID != "" && result.RecordID == recordID
}

func exactAbsent(result dnsproviderremote.ReconcileLookup, err error, recordID string) bool {
	return err == nil && result.TargetComplete && !result.Conflict && !result.Ambiguous && result.RecordID == recordID
}

func cleanupRecordAndFail(
	parent context.Context,
	prepared preparedProvider,
	remote dnsproviderremote.ReconcileRemote,
	config dnsproviderremote.ProviderConfig,
	current dnscheck.ProviderOperation,
	spec recordLifecycleSpec,
	owner string,
	recordID string,
	runID string,
	resourceIndex, providerIndex int,
	writer evidenceWriter,
	evidence *batchEvidence,
	waiter recordStateWaiter,
	reason string,
) bool {
	provider := &evidence.Providers[providerIndex]
	provider.CleanupAttempted = true
	if recordID == "" {
		evidence.Resources[resourceIndex].State = "cleanup_pending"
		_ = writer.write(*evidence)
		return finishProviderFailure(evidence, providerIndex, writer, reason)
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), time.Duration(prepared.input.CleanupTimeoutSeconds)*time.Second)
	defer cancel()
	operation := currentDeleteOperation(current, recordID)
	revision := evidence.Resources[resourceIndex].Revision + 1
	appendPendingStep(provider, strings.TrimSuffix(spec.Kind, "_record")+"_cleanup", stableProviderRequestID(runID, prepared.input.Code, strings.TrimSuffix(spec.Kind, "_record")+"_cleanup"), revision)
	if writer.write(*evidence) != nil {
		evidence.Resources[resourceIndex].State = "cleanup_pending"
		return finishProviderFailure(evidence, providerIndex, writer, reason)
	}
	_, deleteOK, recovered, cleanupReason := mutateWithExactRecovery(cleanupCtx, remote, config, operation)
	absence, lookupErr := remote.Lookup(cleanupCtx, config, operation)
	providerAbsent := deleteOK && exactAbsent(absence, lookupErr, recordID)
	authoritative, public := false, false
	if providerAbsent {
		authoritative, public = waiter(cleanupCtx, prepared, owner, spec.Type, current.Value, false)
	}
	complete := providerAbsent && authoritative && public
	finishPendingStep(provider, complete, cleanupReason, recovered)
	provider.Steps[len(provider.Steps)-1].AuthoritativeConverged = authoritative
	provider.Steps[len(provider.Steps)-1].PublicConverged = public
	provider.CleanupComplete = provider.CleanupComplete && complete
	setResourceIdentity(&evidence.Resources[resourceIndex], recordID, revision, ternary(complete, "absent", "cleanup_pending"))
	_ = writer.write(*evidence)
	return finishProviderFailure(evidence, providerIndex, writer, reason)
}

func setResourceIdentity(resource *resourceEvidence, recordID string, revision uint64, state string) {
	resource.ProviderIdentitySHA256 = identityDigest(resource.Provider, resource.Kind+"_provider_identity", recordID)
	resource.Revision = revision
	resource.State = state
}

func appendPendingStep(provider *providerEvidence, name, requestID string, revision uint64) {
	provider.Steps = append(provider.Steps, stepEvidence{
		Name: name, Status: "pending", Reason: "mutation_journaled",
		ProviderRequestID: requestID, Revision: revision,
	})
}

func finishPendingStep(provider *providerEvidence, ok bool, failureReason string, recovered bool) {
	step := &provider.Steps[len(provider.Steps)-1]
	step.Status = passFail(ok)
	switch {
	case ok && recovered:
		step.Reason = "unknown_outcome_recovered"
	case ok:
		step.Reason = "verified"
	default:
		step.Reason = failureReason
	}
}

func finishProviderFailure(evidence *batchEvidence, index int, writer evidenceWriter, reason string) bool {
	provider := &evidence.Providers[index]
	provider.Status, provider.Reason = "fail", reason
	evidence.Reason = reason
	_ = writer.write(*evidence)
	return false
}

func currentDeleteOperation(current dnscheck.ProviderOperation, recordID string) dnscheck.ProviderOperation {
	return dnscheck.ProviderOperation{
		Sequence: current.Sequence + 1, Action: dnscheck.ProviderDelete, RecordID: recordID,
		Name: current.Name, Type: current.Type, Value: current.Value, TTL: current.TTL,
		Line: current.Line, Weight: current.Weight, Reason: "sandbox_cleanup",
	}
}

func appendStep(provider *providerEvidence, name string, ok bool, reason, requestID string, retryAfter int64) {
	if ok {
		reason = "verified"
	}
	provider.Steps = append(provider.Steps, stepEvidence{
		Name: name, Status: passFail(ok), Reason: reason,
		ProviderRequestID: requestID, RetryAfterSeconds: retryAfter,
	})
}

func stableProviderRequestID(runID, provider, step string) string {
	return dnsproviderremote.ProviderMutationRequestID(stableRequestID(runID, provider, step))
}

func stableRemoteReason(err error, fallback string) string {
	if code := dnsproviderremote.ErrorCodeOf(err); code != "" {
		return string(code)
	}
	return fallback
}

func passFail(ok bool) string { return ternary(ok, "pass", "fail") }

func passFailReason(ok bool, failure string) string { return ternary(ok, "verified", failure) }

func ternary[T any](condition bool, yes, no T) T {
	if condition {
		return yes
	}
	return no
}

func boundedBackoff(attempt int) time.Duration {
	seconds := 1 << min(attempt, 5)
	if seconds > 30 {
		seconds = 30
	}
	return time.Duration(seconds) * time.Second
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func randomRunID() (string, bool) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		clear(value[:])
		return "", false
	}
	result := hex.EncodeToString(value[:])
	clear(value[:])
	return result, true
}

func randomAuthority() (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, bool) {
	values := [5]uuid.UUID{}
	for index := range values {
		value, err := uuid.NewRandom()
		if err != nil {
			return uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, uuid.Nil, false
		}
		values[index] = value
	}
	return values[0], values[1], values[2], values[3], values[4], values[0] != values[1]
}

type sandboxSource struct {
	tenantID, scopeID, providerID, zoneID uuid.UUID
	providerType, zone                    string
	credentials                           map[string]string
}

func (source *sandboxSource) Resolve(ctx context.Context, lookup dnsproviderremote.ProviderLookup) (dnsproviderremote.ProviderConfig, error) {
	if ctx == nil || ctx.Err() != nil || source == nil || lookup.TenantID != source.tenantID ||
		lookup.ScopeID != source.scopeID || lookup.TenantScopeID != source.scopeID ||
		lookup.ProviderID != source.providerID || lookup.ZoneID != source.zoneID ||
		!strings.HasSuffix(lookup.OwnerName, "."+source.zone+".") {
		return dnsproviderremote.ProviderConfig{}, errors.New("source_unavailable")
	}
	return dnsproviderremote.ProviderConfig{
		TenantID: source.tenantID, ScopeID: source.scopeID, TenantScopeID: source.scopeID,
		ProviderID: source.providerID, ProviderType: source.providerType,
		ZoneID: source.zoneID, ZoneName: source.zone, Credentials: cloneCredentials(source.credentials),
	}, nil
}

func (*sandboxSource) OutstandingRemoteTXTHandles(context.Context) ([]acmeworker.ChallengeIdentity, error) {
	return []acmeworker.ChallengeIdentity{}, nil
}

func cloneCredentials(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for name, value := range source {
		result[name] = value
	}
	return result
}

func clearConfigCredentials(config *dnsproviderremote.ProviderConfig) {
	if config == nil {
		return
	}
	for name := range config.Credentials {
		config.Credentials[name] = ""
		delete(config.Credentials, name)
	}
	config.Credentials = nil
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func (wallClock) Sleep(ctx context.Context, duration time.Duration) error {
	if sleepContext(ctx, duration) {
		return nil
	}
	return ctx.Err()
}

var _ dnsproviderremote.StartupSource = (*sandboxSource)(nil)
