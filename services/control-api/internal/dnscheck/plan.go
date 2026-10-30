package dnscheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"unicode"
)

func buildRepairPlan(request CheckRequest) (RepairPlan, error) {
	if !validLineWeight(request.Line, request.Weight) {
		return RepairPlan{}, ErrInvalidInput
	}
	for _, record := range request.Provider.Records {
		if !validLineWeight(record.Line, record.Weight) {
			return RepairPlan{}, ErrInvalidInput
		}
	}
	plan := RepairPlan{
		TenantID:             request.TenantID,
		SiteID:               request.SiteID,
		ZoneID:               request.Provider.ZoneID,
		PreconditionRevision: request.Provider.Revision,
		Operations:           make([]ProviderOperation, 0),
	}
	desired := make(map[RecordType][]string, len(request.Expected))
	weights := make(map[RecordType]map[string]uint32, len(request.Expected))
	for _, expected := range request.Expected {
		desired[expected.Type] = append([]string(nil), expected.Values...)
		weights[expected.Type] = expected.Weights
	}
	weightOf := func(recordType RecordType, value string) uint32 {
		if weight, ok := weights[recordType][value]; ok {
			return weight
		}
		return request.Weight
	}
	current := make(map[RecordType][]ProviderRecord, 3)
	for _, record := range request.Provider.Records {
		current[record.Type] = append(current[record.Type], record)
	}
	for _, recordType := range []RecordType{RecordA, RecordCNAME, RecordAAAA, RecordTXT} {
		desiredValues, wanted := desired[recordType]
		currentRecords := current[recordType]
		if !wanted {
			// TXT records may belong to ACME or mail verification and are outside
			// this reconcile request. Preserve them unless explicitly managed.
			if recordType == RecordTXT {
				continue
			}
			for _, record := range currentRecords {
				plan.Operations = append(plan.Operations, deleteOperation(record, "record_not_expected"))
			}
			continue
		}

		byValue := make(map[string][]ProviderRecord, len(currentRecords))
		for _, record := range currentRecords {
			byValue[record.Value] = append(byValue[record.Value], record)
		}
		missing := make([]string, 0)
		stale := make([]ProviderRecord, 0)
		for _, value := range desiredValues {
			matches := byValue[value]
			if len(matches) == 0 {
				missing = append(missing, value)
				continue
			}
			kept := matches[0]
			weight := weightOf(recordType, value)
			if kept.TTL != request.TTL || kept.Line != request.Line || kept.Weight != weight {
				reason := "ttl_mismatch"
				if kept.Line != request.Line || kept.Weight != weight {
					reason = "routing_mismatch"
				}
				plan.Operations = append(plan.Operations, ProviderOperation{
					Action: ProviderUpdate, RecordID: kept.RecordID, Name: request.Name,
					Type: recordType, Value: value, TTL: request.TTL, Line: request.Line, Weight: weight,
					PreviousValue: kept.Value, PreviousTTL: kept.TTL,
					PreviousLine: kept.Line, PreviousWeight: kept.Weight, Reason: reason,
				})
			}
			for _, duplicate := range matches[1:] {
				plan.Operations = append(plan.Operations, deleteOperation(duplicate, "duplicate_record"))
			}
			delete(byValue, value)
		}
		for _, records := range byValue {
			stale = append(stale, records...)
		}
		sort.Slice(stale, func(i, j int) bool { return stale[i].RecordID < stale[j].RecordID })
		sort.Strings(missing)
		pairs := len(stale)
		if len(missing) < pairs {
			pairs = len(missing)
		}
		for index := 0; index < pairs; index++ {
			plan.Operations = append(plan.Operations, ProviderOperation{
				Action: ProviderUpdate, RecordID: stale[index].RecordID, Name: request.Name,
				Type: recordType, Value: missing[index], TTL: request.TTL, Line: request.Line, Weight: weightOf(recordType, missing[index]),
				PreviousValue: stale[index].Value, PreviousTTL: stale[index].TTL,
				PreviousLine: stale[index].Line, PreviousWeight: stale[index].Weight, Reason: "wrong_value",
			})
		}
		for _, record := range stale[pairs:] {
			plan.Operations = append(plan.Operations, deleteOperation(record, "unexpected_value"))
		}
		for _, value := range missing[pairs:] {
			plan.Operations = append(plan.Operations, ProviderOperation{
				Action: ProviderCreate, Name: request.Name, Type: recordType,
				Value: value, TTL: request.TTL, Line: request.Line, Weight: weightOf(recordType, value), Reason: "missing_record",
			})
		}
	}
	sort.SliceStable(plan.Operations, func(i, j int) bool {
		left, right := plan.Operations[i], plan.Operations[j]
		if providerActionOrder(left.Action) != providerActionOrder(right.Action) {
			return providerActionOrder(left.Action) < providerActionOrder(right.Action)
		}
		if left.Type != right.Type {
			return left.Type < right.Type
		}
		if left.RecordID != right.RecordID {
			return left.RecordID < right.RecordID
		}
		return left.Value < right.Value
	})
	for index := range plan.Operations {
		plan.Operations[index].Sequence = index + 1
	}
	digestInput := struct {
		TenantID             string
		SiteID               string
		ZoneID               string
		PreconditionRevision int64
		Operations           []ProviderOperation
	}{
		TenantID: request.TenantID.String(), SiteID: request.SiteID.String(), ZoneID: request.Provider.ZoneID.String(),
		PreconditionRevision: request.Provider.Revision, Operations: plan.Operations,
	}
	encoded, err := json.Marshal(digestInput)
	if err != nil {
		return RepairPlan{}, err
	}
	digest := sha256.Sum256(encoded)
	plan.Digest = hex.EncodeToString(digest[:])
	return plan, nil
}

func deleteOperation(record ProviderRecord, reason string) ProviderOperation {
	return ProviderOperation{
		Action: ProviderDelete, RecordID: record.RecordID, Name: record.Name,
		Type: record.Type, Value: record.Value, TTL: record.TTL,
		Line: record.Line, Weight: record.Weight, Reason: reason,
	}
}

func validLineWeight(line string, weight uint32) bool {
	if weight > 100 || len(line) > 64 || line != strings.TrimSpace(line) {
		return false
	}
	for _, character := range line {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func providerActionOrder(action ProviderAction) int {
	switch action {
	case ProviderDelete:
		return 0
	case ProviderUpdate:
		return 1
	case ProviderCreate:
		return 2
	default:
		return 3
	}
}
