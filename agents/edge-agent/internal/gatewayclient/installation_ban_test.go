package gatewayclient

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type installationBanApplierStub struct{ notice, ticket []byte }

func (stub *installationBanApplierStub) ApplyInstallationBan(_ context.Context, notice, ticket []byte) InstallationBanResult {
	stub.notice, stub.ticket = notice, ticket
	return InstallationBanResult{Applied: true, Status: "banned"}
}

func TestInstallationBanNegotiationAndReceipt(t *testing.T) {
	enabled := &agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET, ApiVersion: 1}}}
	if _, err := negotiateInstallationBanV1(enabled, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("enabled without being advertised: %v", err)
	}
	stub := &installationBanApplierStub{}
	if on, err := negotiateInstallationBanV1(enabled, stub); err != nil || !on {
		t.Fatalf("negotiate: %v %v", on, err)
	}
	nodeID := uuid.NewString()
	client := &Client{config: Config{NodeID: nodeID}, installationBan: stub}
	notice := []byte(`signed-notice`)
	digest := sha256.Sum256(notice)
	command := &agentv1.InstallationBanCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: 7, NoticeJson: notice, NoticeSha256: digest[:]}
	receipt, err := client.installationBanReceipt(t.Context(), command, time.Now())
	if err != nil || string(stub.notice) != "signed-notice" || stub.ticket != nil {
		t.Fatalf("receipt err %v notice %q ticket %v", err, stub.notice, stub.ticket)
	}
	if receipt.NodeId != nodeID || receipt.CommandEventId != command.Event.EventId || receipt.Revision != 7 ||
		!receipt.Applied || receipt.Status != "banned" {
		t.Fatalf("receipt = %v", receipt)
	}
	command.NoticeSha256[0] ^= 1
	if _, err := client.installationBanReceipt(t.Context(), command, time.Now()); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("digest mismatch accepted: %v", err)
	}
}

type installationBanTicketStub struct{ result InstallationBanResult }

func (stub installationBanTicketStub) ApplyInstallationBan(context.Context, []byte, []byte) InstallationBanResult {
	return stub.result
}

// PF09: the receipt carries the held ticket's times (the console shows the last
// ticket and the days left); before the first ticket both stay unset.
func TestInstallationBanReceiptCarriesTicketTimes(t *testing.T) {
	nodeID := uuid.NewString()
	issued := time.Unix(1_900_000_000, 0).UTC()
	command := &agentv1.InstallationBanCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: 3}
	held := &Client{config: Config{NodeID: nodeID}, installationBan: installationBanTicketStub{InstallationBanResult{
		Applied: true, Status: "serving", TicketIssuedAt: issued, TicketNotAfter: issued.Add(7 * 24 * time.Hour)}}}
	receipt, err := held.installationBanReceipt(t.Context(), command, time.Now())
	if err != nil || !receipt.TicketIssuedTime.AsTime().Equal(issued) ||
		!receipt.TicketNotAfterTime.AsTime().Equal(issued.Add(7*24*time.Hour)) {
		t.Fatalf("receipt with a ticket = %v (%v)", receipt, err)
	}
	none := &Client{config: Config{NodeID: nodeID}, installationBan: installationBanTicketStub{InstallationBanResult{
		Status: "no_ticket"}}}
	receipt, err = none.installationBanReceipt(t.Context(), command, time.Now())
	if err != nil || receipt.TicketIssuedTime != nil || receipt.TicketNotAfterTime != nil {
		t.Fatalf("receipt before the first ticket = %v (%v)", receipt, err)
	}
}

type frozenInstallationBan struct {
	installationBanTicketStub
	frozen bool
}

func (stub *frozenInstallationBan) Frozen() bool { return stub.frozen }

// 票据过期的节点继续服务已有配置，但拒绝新发布（APPLY），
// 失败状态可重试并写明原因；回滚照常执行。解除冻结后新发布照常。
func TestFrozenNodeRefusesNewPublicationsButRollsBack(t *testing.T) {
	runtime := &fakeArtifactSets{}
	client, privateKey := artifactSetClient(t, runtime)
	ban := &frozenInstallationBan{frozen: true}
	client.installationBan = ban
	segment := []byte("frozen segment")
	statuses := runArtifactSetCommand(t, client, artifactSetCommand(artifactset.MediaTypeSegment, segment, privateKey), segment)
	last := statuses[len(statuses)-1]
	if last.State != agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED || last.Error == nil ||
		last.Error.Code != commonv1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION || !last.Error.Retryable ||
		!strings.Contains(last.Error.Message, InstallationFrozenReason) || len(runtime.objects) != 0 {
		t.Fatalf("frozen apply: %v objects %d", last, len(runtime.objects))
	}
	if !client.installationFrozen() {
		t.Fatal("frozen applier not seen")
	}
	ban.frozen = false
	statuses = runArtifactSetCommand(t, client, artifactSetCommand(artifactset.MediaTypeSegment, segment, privateKey), segment)
	if last := statuses[len(statuses)-1]; last.State == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED {
		t.Fatalf("unfrozen apply failed: %v", last)
	}
	// an applier without Frozen (older wiring) never freezes
	client.installationBan = installationBanTicketStub{}
	if client.installationFrozen() {
		t.Fatal("applier without Frozen must not freeze")
	}
}

type countingUpgradeRuntime struct {
	legacyTestUpgradeRuntime
	accepted, recovered int
}

func (runtime *countingUpgradeRuntime) AcceptCommand(context.Context, []byte) error {
	runtime.accepted++
	return nil
}

func (runtime *countingUpgradeRuntime) Recover(context.Context) error {
	runtime.recovered++
	return nil
}

// 冻结的节点不接受新的升级命令（不落盘，主控之后重投）；已接受的升级照常恢复。
func TestFrozenNodeRefusesNewUpgrades(t *testing.T) {
	upgrades := &countingUpgradeRuntime{}
	ban := &frozenInstallationBan{frozen: true}
	client := &Client{installationBan: ban, upgrades: upgrades}
	if err := client.runUpgradeWork(t.Context(), upgradeWorkItem{encoded: []byte("command")}); err != nil || upgrades.accepted != 0 {
		t.Fatalf("frozen accept: %v accepted %d", err, upgrades.accepted)
	}
	if err := client.runUpgradeWork(t.Context(), upgradeWorkItem{recover: true}); err != nil || upgrades.recovered != 1 {
		t.Fatalf("frozen recover: %v recovered %d", err, upgrades.recovered)
	}
	ban.frozen = false
	if err := client.runUpgradeWork(t.Context(), upgradeWorkItem{encoded: []byte("command")}); err != nil || upgrades.accepted != 1 {
		t.Fatalf("unfrozen accept: %v accepted %d", err, upgrades.accepted)
	}
}
