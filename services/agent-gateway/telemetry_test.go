package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testTelemetryTenantID        = "018f47a2-5b9c-7d31-8a60-104c9c0b7180"
	testTelemetrySiteID          = "018f47a2-5b9c-7d31-8a60-104c9c0b7181"
	testTelemetryConfigVersionID = "018f47a2-5b9c-7d31-8a60-104c9c0b7182"
	testTelemetryInstallationID  = "control-runtime-test"
)

type telemetryAuthorizationState struct {
	state   controlv1.NodeAdministrativeState
	revoked bool
	tenant  string
	site    string
	config  string
}

type telemetryTestControl struct {
	*fakeControl
	mu     sync.Mutex
	states []telemetryAuthorizationState
	calls  int
}

func (c *telemetryTestControl) GetNodeAuthorization(_ context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	c.mu.Lock()
	index := c.calls
	if index >= len(c.states) {
		index = len(c.states) - 1
	}
	state := c.states[index]
	c.calls++
	c.mu.Unlock()
	if state.state == controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_UNSPECIFIED {
		state.state = controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE
	}
	if state.tenant == "" {
		state.tenant = testTelemetryTenantID
	}
	if state.site == "" {
		state.site = testTelemetrySiteID
	}
	if state.config == "" {
		state.config = testTelemetryConfigVersionID
	}
	return &controlv1.GetNodeAuthorizationResponse{
		NodeId: request.NodeId, AdministrativeState: state.state, ConnectionAllowed: true,
		CertificateRevoked: state.revoked, AcceptedProtocolVersions: versionRange(1, 0),
		SnapshotExpirationTime: timestamppb.New(time.Now().Add(time.Hour)), ArtifactEncryptionKeyId: "artifact-key",
		InstallationId: testTelemetryInstallationID, TenantId: state.tenant,
		TelemetrySiteScopes: []*controlv1.TelemetrySiteScope{{
			SiteId: state.site, TenantId: state.tenant, ConfigVersionId: state.config,
		}},
	}, nil
}

type scriptedTelemetryPublisher struct {
	mu           sync.Mutex
	publications []TelemetryPublication
	results      []TelemetryPublishResult
	errors       []error
	active       int
	maxActive    int
}

func (p *scriptedTelemetryPublisher) Publish(_ context.Context, publication TelemetryPublication) (TelemetryPublishResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active++
	if p.active > p.maxActive {
		p.maxActive = p.active
	}
	defer func() { p.active-- }()
	index := len(p.publications)
	p.publications = append(p.publications, publication)
	var result TelemetryPublishResult
	if index < len(p.results) {
		result = p.results[index]
	}
	if index < len(p.errors) {
		return result, p.errors[index]
	}
	return result, nil
}

func (p *scriptedTelemetryPublisher) Check(context.Context) error { return nil }

type telemetryTestStream struct {
	ctx       context.Context
	requests  []*agentv1.StreamTelemetryRequest
	responses []*agentv1.StreamTelemetryResponse
	mu        sync.Mutex
}

func (s *telemetryTestStream) Recv() (*agentv1.StreamTelemetryRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		return nil, io.EOF
	}
	request := s.requests[0]
	s.requests = s.requests[1:]
	return request, nil
}

func (s *telemetryTestStream) Send(response *agentv1.StreamTelemetryResponse) error {
	s.mu.Lock()
	s.responses = append(s.responses, response)
	s.mu.Unlock()
	return nil
}

func (s *telemetryTestStream) SetHeader(metadata.MD) error  { return nil }
func (s *telemetryTestStream) SendHeader(metadata.MD) error { return nil }
func (s *telemetryTestStream) SetTrailer(metadata.MD)       {}
func (s *telemetryTestStream) Context() context.Context     { return s.ctx }
func (s *telemetryTestStream) SendMsg(any) error            { return nil }
func (s *telemetryTestStream) RecvMsg(any) error            { return nil }

func TestStreamTelemetryAcknowledgesOnlyDurableContiguousPrefix(t *testing.T) {
	publisher := &scriptedTelemetryPublisher{
		results: []TelemetryPublishResult{{Duplicate: true}, {}},
		errors:  []error{nil, errors.New("publish outcome unknown")},
	}
	gateway := newTelemetryGateway(t, &telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{{}}}, publisher)
	batch := telemetryBatch(t, 1, 2)
	stream := &telemetryTestStream{ctx: authenticatedTestContext(t), requests: []*agentv1.StreamTelemetryRequest{
		telemetryHelloRequest(0, 1), telemetryBatchRequest(batch, 2),
	}}

	err := gateway.StreamTelemetry(stream)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("StreamTelemetry code = %v, want Unavailable", status.Code(err))
	}
	if len(stream.responses) != 3 || stream.responses[0].GetHello() == nil || stream.responses[1].GetAck() == nil || stream.responses[2].GetError() == nil {
		t.Fatalf("telemetry responses = %+v", stream.responses)
	}
	ack := stream.responses[1].GetAck()
	if ack.AcceptedRecordCount != 1 || ack.AcceptedThroughSequence != 1 ||
		ack.AcceptedThroughMessageId != batch.Records[0].MessageId || ack.AcceptedThroughEventId != batch.Records[0].LastEventId ||
		ack.DuplicateRecordCount != 1 || ack.RetryAfterDuration == nil {
		t.Fatalf("partial durable ACK = %+v", ack)
	}
	if stream.responses[2].GetError().Error.Code != commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE || !stream.responses[2].GetError().Error.Retryable {
		t.Fatalf("publication error response = %+v", stream.responses[2].GetError())
	}
	publisher.mu.Lock()
	defer publisher.mu.Unlock()
	if len(publisher.publications) != 2 || publisher.maxActive != 1 {
		t.Fatalf("publisher calls=%d max_active=%d", len(publisher.publications), publisher.maxActive)
	}
	for _, publication := range publisher.publications {
		if publication.NodeID != testNodeID || publication.TenantID != testTelemetryTenantID ||
			publication.SiteID != testTelemetrySiteID || publication.ConfigVersionID != testTelemetryConfigVersionID ||
			publication.InstallationID != testTelemetryInstallationID {
			t.Fatalf("publication identity was not certificate-authoritative: %+v", publication)
		}
	}
	snapshot := gateway.telemetry.health.Snapshot()
	if snapshot.AcceptedRecords != 1 || snapshot.DuplicateRecords != 1 || snapshot.PublishFailures != 1 || !snapshot.Degraded {
		t.Fatalf("telemetry health = %+v", snapshot)
	}
}

func TestStreamTelemetryRejectsForgedIdentityAndRefreshesAuthorization(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*telemetryAccessEnvelope)
	}{
		{name: "node", mutate: func(envelope *telemetryAccessEnvelope) { envelope.NodeID = uuid.NewString() }},
		{name: "tenant", mutate: func(envelope *telemetryAccessEnvelope) { envelope.TenantID = uuid.NewString() }},
		{name: "site", mutate: func(envelope *telemetryAccessEnvelope) { envelope.Events[0].SiteID = uuid.NewString() }},
		{name: "config", mutate: func(envelope *telemetryAccessEnvelope) { envelope.Events[0].ConfigVersion = uuid.NewString() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publisher := &scriptedTelemetryPublisher{}
			gateway := newTelemetryGateway(t, &telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{{}}}, publisher)
			batch := telemetryBatch(t, 1, 1)
			var envelope telemetryAccessEnvelope
			if err := json.Unmarshal(batch.Records[0].Payload, &envelope); err != nil {
				t.Fatal(err)
			}
			test.mutate(&envelope)
			batch.Records[0].Payload, _ = json.Marshal(envelope)
			stream := &telemetryTestStream{ctx: authenticatedTestContext(t), requests: []*agentv1.StreamTelemetryRequest{
				telemetryHelloRequest(0, 1), telemetryBatchRequest(batch, 2),
			}}
			if err := gateway.StreamTelemetry(stream); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("forged identity code = %v", status.Code(err))
			}
			if len(publisher.publications) != 0 {
				t.Fatal("forged telemetry reached the publisher")
			}
		})
	}

	control := &telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{{}, {revoked: true}}}
	publisher := &scriptedTelemetryPublisher{}
	gateway := newTelemetryGateway(t, control, publisher)
	stream := &telemetryTestStream{ctx: authenticatedTestContext(t), requests: []*agentv1.StreamTelemetryRequest{
		telemetryHelloRequest(0, 1), telemetryBatchRequest(telemetryBatch(t, 1, 1), 2),
	}}
	if err := gateway.StreamTelemetry(stream); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked refresh code = %v, want PermissionDenied", status.Code(err))
	}
	if control.calls != 2 || len(publisher.publications) != 0 {
		t.Fatalf("authorization calls=%d publications=%d", control.calls, len(publisher.publications))
	}
}

func TestStreamTelemetryAllowsDrainingWithoutDeploymentAuthority(t *testing.T) {
	control := &telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{
		{state: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING},
	}}
	publisher := &scriptedTelemetryPublisher{}
	gateway := newTelemetryGateway(t, control, publisher)
	stream := &telemetryTestStream{ctx: authenticatedTestContext(t), requests: []*agentv1.StreamTelemetryRequest{
		telemetryHelloRequest(0, 1), telemetryBatchRequest(telemetryBatch(t, 1, 1), 2),
	}}
	if err := gateway.StreamTelemetry(stream); err != nil {
		t.Fatal(err)
	}
	if len(stream.responses) != 2 || stream.responses[1].GetAck() == nil || len(publisher.publications) != 1 {
		t.Fatalf("draining telemetry responses=%+v publications=%d", stream.responses, len(publisher.publications))
	}
}

func TestStreamTelemetryUsesIndependentFenceAndHonorsCancellation(t *testing.T) {
	t.Run("cross gateway fence", func(t *testing.T) {
		telemetrySessions := NewMemorySessionCoordinator()
		control := &telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{{}}}
		firstGateway := newTelemetryGatewayWithCoordinator(t, control, &scriptedTelemetryPublisher{}, telemetrySessions)
		secondGateway := newTelemetryGatewayWithCoordinator(t, control, &scriptedTelemetryPublisher{}, telemetrySessions)
		firstContext, cancelFirst := context.WithCancel(authenticatedTestContext(t))
		defer cancelFirst()
		firstStream := newLiveTelemetryStream(firstContext)
		firstDone := make(chan error, 1)
		go func() { firstDone <- firstGateway.StreamTelemetry(firstStream) }()
		firstStream.receive <- telemetryHelloRequest(0, 1)
		if response := receiveTelemetryTestResponse(t, firstStream.sent); response.GetHello() == nil {
			t.Fatalf("first telemetry response = %+v", response)
		}

		secondContext, cancelSecond := context.WithCancel(authenticatedTestContext(t))
		defer cancelSecond()
		secondStream := newLiveTelemetryStream(secondContext)
		secondDone := make(chan error, 1)
		go func() { secondDone <- secondGateway.StreamTelemetry(secondStream) }()
		secondStream.receive <- telemetryHelloRequest(0, 1)
		if response := receiveTelemetryTestResponse(t, secondStream.sent); response.GetHello() == nil {
			t.Fatalf("second telemetry response = %+v", response)
		}
		select {
		case err := <-firstDone:
			if status.Code(err) != codes.Aborted {
				t.Fatalf("superseded telemetry stream code = %v", status.Code(err))
			}
		case <-time.After(time.Second):
			t.Fatal("superseded telemetry stream did not stop")
		}
		cancelSecond()
		if err := <-secondDone; status.Code(err) != codes.Canceled {
			t.Fatalf("second telemetry stream code = %v", status.Code(err))
		}
	})

	t.Run("cancelled publish has no ACK and one in flight", func(t *testing.T) {
		publisher := &blockingTelemetryPublisher{started: make(chan struct{})}
		gateway := newTelemetryGateway(t, &telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{{}}}, publisher)
		streamContext, cancel := context.WithCancel(authenticatedTestContext(t))
		stream := newLiveTelemetryStream(streamContext)
		done := make(chan error, 1)
		go func() { done <- gateway.StreamTelemetry(stream) }()
		stream.receive <- telemetryHelloRequest(0, 1)
		if response := receiveTelemetryTestResponse(t, stream.sent); response.GetHello() == nil {
			t.Fatalf("telemetry response = %+v", response)
		}
		stream.receive <- telemetryBatchRequest(telemetryBatch(t, 1, 2), 2)
		select {
		case <-publisher.started:
		case <-time.After(time.Second):
			t.Fatal("telemetry publisher did not start")
		}
		cancel()
		if err := <-done; status.Code(err) != codes.Canceled {
			t.Fatalf("cancelled telemetry stream code = %v", status.Code(err))
		}
		if publisher.maxActive.Load() != 1 || publisher.calls.Load() != 1 {
			t.Fatalf("publisher active=%d calls=%d", publisher.maxActive.Load(), publisher.calls.Load())
		}
		for {
			select {
			case response := <-stream.sent:
				if response.GetAck() != nil {
					t.Fatal("cancelled PubAck-unknown publication was acknowledged")
				}
			default:
				return
			}
		}
	})
}

type liveTelemetryStream struct {
	ctx     context.Context
	receive chan *agentv1.StreamTelemetryRequest
	sent    chan *agentv1.StreamTelemetryResponse
}

func newLiveTelemetryStream(ctx context.Context) *liveTelemetryStream {
	return &liveTelemetryStream{
		ctx: ctx, receive: make(chan *agentv1.StreamTelemetryRequest, 2),
		sent: make(chan *agentv1.StreamTelemetryResponse, 8),
	}
}

func (s *liveTelemetryStream) Recv() (*agentv1.StreamTelemetryRequest, error) {
	select {
	case request := <-s.receive:
		return request, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *liveTelemetryStream) Send(response *agentv1.StreamTelemetryResponse) error {
	select {
	case s.sent <- response:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *liveTelemetryStream) SetHeader(metadata.MD) error  { return nil }
func (s *liveTelemetryStream) SendHeader(metadata.MD) error { return nil }
func (s *liveTelemetryStream) SetTrailer(metadata.MD)       {}
func (s *liveTelemetryStream) Context() context.Context     { return s.ctx }
func (s *liveTelemetryStream) SendMsg(any) error            { return nil }
func (s *liveTelemetryStream) RecvMsg(any) error            { return nil }

func receiveTelemetryTestResponse(t *testing.T, responses <-chan *agentv1.StreamTelemetryResponse) *agentv1.StreamTelemetryResponse {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for telemetry response")
		return nil
	}
}

type blockingTelemetryPublisher struct {
	started   chan struct{}
	startOnce sync.Once
	calls     atomic.Int32
	active    atomic.Int32
	maxActive atomic.Int32
}

func (p *blockingTelemetryPublisher) Publish(ctx context.Context, _ TelemetryPublication) (TelemetryPublishResult, error) {
	p.calls.Add(1)
	active := p.active.Add(1)
	for {
		maximum := p.maxActive.Load()
		if active <= maximum || p.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	p.startOnce.Do(func() { close(p.started) })
	defer p.active.Add(-1)
	<-ctx.Done()
	return TelemetryPublishResult{}, ctx.Err()
}

func (p *blockingTelemetryPublisher) Check(context.Context) error { return nil }

func TestTelemetryValidationRejectsDuplicateKeysAndUnknownFields(t *testing.T) {
	authorization := telemetryAuthorization{
		installationID: testTelemetryInstallationID,
		tenantID:       testTelemetryTenantID,
		configBySite: map[telemetryScopeKey]string{
			{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}: testTelemetryTenantID,
		},
	}
	batch := telemetryBatch(t, 1, 1)
	record := batch.Records[0]
	record.Payload = append(record.Payload[:len(record.Payload)-1], []byte(`,"tenant_id":"`+testTelemetryTenantID+`"}`)...)
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization, DefaultTelemetryConfig(), time.Now()); err == nil {
		t.Fatal("duplicate JSON key was accepted")
	}
	batch = telemetryBatch(t, 1, 1)
	record = batch.Records[0]
	record.Payload = append(record.Payload[:len(record.Payload)-1], []byte(`,"unexpected":true}`)...)
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization, DefaultTelemetryConfig(), time.Now()); err == nil {
		t.Fatal("unknown JSON field was accepted")
	}
}

func TestTelemetryValidationAcceptsSanitizedCaptureFields(t *testing.T) {
	requestBody := telemetryNestedCaptureBody(8)
	requestBody["password"] = "[REDACTED]"
	captures := map[string]any{
		"request_headers": map[string]any{
			"Authorization": "[REDACTED]",
			"X-Large":       strings.Repeat("h", 16<<10),
		},
		"response_headers": map[string]any{
			"Set-Cookie": "[REDACTED]",
			"X-Cache":    "HIT",
		},
		"request_body": requestBody,
		"response_body": map[string]any{
			"token":  "[REDACTED]",
			"result": strings.Repeat("b", 70<<10),
		},
	}
	for _, kind := range []agentv1.TelemetryKind{
		agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1,
		agentv1.TelemetryKind_TELEMETRY_KIND_SECURITY_V1,
	} {
		t.Run(kind.String(), func(t *testing.T) {
			batch := telemetryCaptureBatch(t, kind, captures)
			if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now()); err != nil {
				t.Fatalf("sanitized capture rejected: %v", err)
			}
		})
	}
}

func TestTelemetryValidationRejectsUnsafeCaptureFields(t *testing.T) {
	tests := []struct {
		name     string
		captures map[string]any
	}{
		{name: "unredacted sensitive request header", captures: map[string]any{
			"request_headers": map[string]any{"Authorization": "Bearer secret"},
		}},
		{name: "unredacted nested response body", captures: map[string]any{
			"response_body": map[string]any{"result": map[string]any{"api_key": "secret"}},
		}},
		{name: "sensitive body value is not a string", captures: map[string]any{
			"request_body": map[string]any{"password": nil},
		}},
		{name: "invalid header name", captures: map[string]any{
			"request_headers": map[string]any{"bad header": "value"},
		}},
		{name: "header value has wrong type", captures: map[string]any{
			"response_headers": map[string]any{"X-Count": 1},
		}},
		{name: "header value exceeds maximum", captures: map[string]any{
			"response_headers": map[string]any{"X-Large": strings.Repeat("h", (16<<10)+1)},
		}},
		{name: "body is not an object", captures: map[string]any{
			"response_body": []any{"value"},
		}},
		{name: "body key exceeds maximum", captures: map[string]any{
			"request_body": map[string]any{strings.Repeat("k", 129): "value"},
		}},
		{name: "body exceeds recursion depth", captures: map[string]any{
			"response_body": telemetryNestedCaptureBody(9),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := telemetryCaptureBatch(t, agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, test.captures)
			if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now()); err == nil {
				t.Fatal("unsafe capture was accepted")
			}
		})
	}
}

func TestTelemetryValidationRejectsNestedCaptureDuplicateKeys(t *testing.T) {
	batch := telemetryCaptureBatch(t, agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, map[string]any{
		"request_body": map[string]any{"profile": map[string]any{"name": "alice"}},
	})
	record := batch.Records[0]
	record.Payload = bytes.Replace(record.Payload, []byte(`"name":"alice"`), []byte(`"name":"alice","name":"forged"`), 1)
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now()); err == nil {
		t.Fatal("duplicate nested capture key was accepted")
	}
}

func TestTelemetryValidationRejectsInvalidUTF8Capture(t *testing.T) {
	batch := telemetryCaptureBatch(t, agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, map[string]any{
		"request_headers": map[string]any{"X-Test": "valid"},
	})
	record := batch.Records[0]
	original := append([]byte(nil), record.Payload...)
	needle := []byte(`"X-Test":"valid"`)
	replacement := append([]byte(`"X-Test":"`), 0xff)
	replacement = append(replacement, []byte(`"`)...)
	record.Payload = bytes.Replace(record.Payload, needle, replacement, 1)
	if bytes.Equal(record.Payload, original) {
		t.Fatal("test did not inject invalid UTF-8")
	}
	if _, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), time.Now()); err == nil {
		t.Fatal("invalid UTF-8 capture was accepted")
	}
}

func TestTelemetryValidationRejectsStableIDConflicts(t *testing.T) {
	authorization := telemetryAuthorization{
		installationID: testTelemetryInstallationID,
		tenantID:       testTelemetryTenantID,
		configBySite: map[telemetryScopeKey]string{
			{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}: testTelemetryTenantID,
		},
	}
	validate := func(batch *agentv1.TelemetryBatch) error {
		_, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization, DefaultTelemetryConfig(), time.Now())
		return err
	}

	messageConflict := telemetryBatch(t, 1, 1)
	var envelope telemetryAccessEnvelope
	if err := json.Unmarshal(messageConflict.Records[0].Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.MessageID = "msg_conflicting_identity"
	messageConflict.Records[0].MessageId = envelope.MessageID
	messageConflict.Records[0].Payload = marshalTelemetryEnvelope(t, envelope)
	messageConflict.BatchId = telemetryBatchID(messageConflict.Records)
	if err := validate(messageConflict); err == nil {
		t.Fatal("non-deterministic message ID was accepted")
	}

	eventConflict := telemetryBatch(t, 1, 1)
	if err := json.Unmarshal(eventConflict.Records[0].Payload, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Events[0].EventID = "event_" + uuid.NewString()
	eventConflict.Records[0].LastEventId = envelope.Events[0].EventID
	eventConflict.Records[0].Payload = marshalTelemetryEnvelope(t, envelope)
	eventConflict.BatchId = telemetryBatchID(eventConflict.Records)
	if err := validate(eventConflict); err == nil {
		t.Fatal("changed event identity with the old message ID was accepted")
	}

	batchConflict := telemetryBatch(t, 1, 1)
	batchConflict.BatchId = "batch_conflicting_identity"
	if err := validate(batchConflict); err == nil {
		t.Fatal("non-deterministic batch ID was accepted")
	}
}

func marshalTelemetryEnvelope(t *testing.T, envelope telemetryAccessEnvelope) []byte {
	t.Helper()
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func telemetryTestAuthorization() telemetryAuthorization {
	return telemetryAuthorization{
		installationID: testTelemetryInstallationID,
		tenantID:       testTelemetryTenantID,
		configBySite: map[telemetryScopeKey]string{
			{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}: testTelemetryTenantID,
		},
	}
}

func telemetryCaptureBatch(t *testing.T, kind agentv1.TelemetryKind, captures map[string]any) *agentv1.TelemetryBatch {
	t.Helper()
	return telemetryCaptureBatchFor(t, kind, testTelemetryTenantID, testTelemetrySiteID, testTelemetryConfigVersionID, captures)
}

func telemetryCaptureBatchFor(t *testing.T, kind agentv1.TelemetryKind, tenantID, siteID, configVersionID string, captures map[string]any) *agentv1.TelemetryBatch {
	t.Helper()
	eventID := "event_" + uuid.NewString()
	typeName := "access.v1"
	event := map[string]any{
		"metric_version":    telemetryMetricVersion,
		"event_id":          eventID,
		"occurred_at":       time.Now().UTC(),
		"tenant_id":         tenantID,
		"site_id":           siteID,
		"node_id":           testNodeID,
		"config_version_id": configVersionID,
		"host":              "example.test",
		"path":              "/capture",
		"client_ip":         "192.0.2.1",
		"status_code":       200,
		"request_bytes":     1,
		"response_bytes":    2,
	}
	if kind == agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1 {
		event["method"] = "GET"
		event["protocol"] = "HTTP/2"
		event["cache_status"] = "HIT"
		event["duration_us"] = 1
	} else {
		typeName = "security.v1"
		event["method"] = "GET"
		event["listen_port"] = 443
		event["protocol"] = "https"
		event["request_class"] = "standard"
		event["event_type"] = "waf"
		event["action"] = "block"
		event["severity"] = "high"
	}
	for name, value := range captures {
		event[name] = value
	}
	messageID := telemetryMessageID(testNodeID, tenantID, siteID, configVersionID, typeName, eventID, eventID)
	payload, err := json.Marshal(map[string]any{
		"schema_version": telemetrySchemaVersion,
		"type":           typeName,
		"message_id":     messageID,
		"produced_at":    time.Now().UTC(),
		"tenant_id":      tenantID,
		"node_id":        testNodeID,
		"events":         []any{event},
	})
	if err != nil {
		t.Fatal(err)
	}
	record := &agentv1.TelemetryRecord{
		Kind: kind, MessageId: messageID, FirstSequence: 1, LastSequence: 1,
		LastEventId: eventID, EventCount: 1, Payload: payload,
	}
	return &agentv1.TelemetryBatch{
		BatchId:       telemetryBatchID([]*agentv1.TelemetryRecord{record}),
		FirstSequence: 1, LastSequence: 1, Records: []*agentv1.TelemetryRecord{record},
	}
}

func telemetryNestedCaptureBody(depth int) map[string]any {
	var value any = "leaf"
	for index := 0; index < depth; index++ {
		value = map[string]any{"level": value}
	}
	return map[string]any{"root": value}
}

func TestTelemetryAuthorizationAcceptsBoundedInstallationIdentifiers(t *testing.T) {
	response := &controlv1.GetNodeAuthorizationResponse{
		InstallationId: "control-runtime-test", TenantId: testTelemetryTenantID,
		TelemetrySiteScopes: []*controlv1.TelemetrySiteScope{{
			SiteId: testTelemetrySiteID, TenantId: testTelemetryTenantID, ConfigVersionId: testTelemetryConfigVersionID,
		}},
	}
	if _, err := validateTelemetryAuthorization(response); err != nil {
		t.Fatalf("valid non-UUID installation ID rejected: %v", err)
	}
	for _, invalid := range []string{"", " padded", "has/slash", strings.Repeat("a", 129)} {
		response.InstallationId = invalid
		if _, err := validateTelemetryAuthorization(response); err == nil {
			t.Fatalf("invalid installation ID %q was accepted", invalid)
		}
	}
}

func newTelemetryGateway(t *testing.T, control ControlPlane, publisher TelemetryPublisher) *Gateway {
	return newTelemetryGatewayWithCoordinator(t, control, publisher, NewMemorySessionCoordinator())
}

func newTelemetryGatewayWithCoordinator(
	t *testing.T,
	control ControlPlane,
	publisher TelemetryPublisher,
	telemetrySessions SessionCoordinator,
) *Gateway {
	t.Helper()
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-telemetry-test"
	config.GatewayVersion = "test"
	service, err := New(config, control, NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureTelemetry(DefaultTelemetryConfig(), publisher, telemetrySessions, NewTelemetryHealth()); err != nil {
		t.Fatal(err)
	}
	return service
}

func telemetryHelloRequest(lastAcknowledged, streamSequence uint64) *agentv1.StreamTelemetryRequest {
	return &agentv1.StreamTelemetryRequest{
		Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: streamSequence},
		Payload: &agentv1.StreamTelemetryRequest_Hello{Hello: &agentv1.TelemetryClientHello{
			SupportedProtocolVersions: versionRange(1, 0), LastDurableAcknowledgedSequence: lastAcknowledged,
			BootId: uuid.NewString(),
		}},
	}
}

func telemetryBatchRequest(batch *agentv1.TelemetryBatch, streamSequence uint64) *agentv1.StreamTelemetryRequest {
	return &agentv1.StreamTelemetryRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: streamSequence},
		Payload: &agentv1.StreamTelemetryRequest_Batch{Batch: batch},
	}
}

func telemetryBatch(t *testing.T, first, last uint64) *agentv1.TelemetryBatch {
	t.Helper()
	records := make([]*agentv1.TelemetryRecord, 0, last-first+1)
	for sequence := first; sequence <= last; sequence++ {
		eventID := "event_" + uuid.NewString()
		messageID := telemetryMessageID(testNodeID, testTelemetryTenantID, testTelemetrySiteID,
			testTelemetryConfigVersionID, "access.v1", eventID, eventID)
		envelope := telemetryAccessEnvelope{
			SchemaVersion: telemetrySchemaVersion, Type: "access.v1", MessageID: messageID,
			ProducedAt: time.Now().UTC(), TenantID: testTelemetryTenantID, NodeID: testNodeID,
			Events: []telemetryAccessEvent{{
				MetricVersion: telemetryMetricVersion, EventID: eventID, OccurredAt: time.Now().UTC(),
				TenantID: testTelemetryTenantID, SiteID: testTelemetrySiteID, NodeID: testNodeID,
				ConfigVersion: testTelemetryConfigVersionID,
				Host:          "example.test", Path: "/", ClientIP: "192.0.2.1", Method: "GET", Protocol: "HTTP/2",
				CacheStatus: "HIT", StatusCode: 200, ResponseBytes: 1, DurationUS: 1,
			}},
		}
		payload, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, &agentv1.TelemetryRecord{
			Kind: agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, MessageId: messageID,
			FirstSequence: sequence, LastSequence: sequence, LastEventId: eventID, EventCount: 1, Payload: payload,
		})
		if sequence == ^uint64(0) {
			break
		}
	}
	return &agentv1.TelemetryBatch{BatchId: telemetryBatchID(records), FirstSequence: first, LastSequence: last, Records: records}
}
