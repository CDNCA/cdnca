package node

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

var (
	writeMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	timeOfDayPattern     = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]$`)
	interfacePattern     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
	countryCodePattern   = regexp.MustCompile(`^[A-Z]{2}$`)
)

const (
	defaultTokenTTL = 10 * time.Minute
	minTokenTTL     = time.Minute
	maxTokenTTL     = 24 * time.Hour
	// MaxListLimit matches the largest page size exposed by the admin inventory UI.
	MaxListLimit = 300
)

type Service struct {
	store        *Store
	registration registrationKeys
}

func NewService(store *Store) *Service {
	return &Service{store: store}
}

func (s *Service) CreateNode(
	ctx context.Context,
	actor Actor,
	request CreateRequest,
) (CreateResult, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Description = strings.TrimSpace(request.Description)
	request.Region = strings.TrimSpace(request.Region)
	if !validActor(actor) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return CreateResult{}, ErrInvalidInput
	}
	for _, check := range []error{
		nodeText("name", request.Name, 1, 128), nodeText("description", request.Description, 0, 1024),
		nodeText("region", request.Region, 0, 64),
	} {
		if check != nil {
			return CreateResult{}, check
		}
	}
	var err error
	if request.IPv4, err = nodeIP("ipv4", request.IPv4, true); err != nil {
		return CreateResult{}, err
	}
	if request.IPv6, err = nodeIP("ipv6", request.IPv6, false); err != nil {
		return CreateResult{}, err
	}
	if request.IssueToken {
		purpose, ttl, err := validateTokenRequest(request.TokenPurpose, request.TokenTTL)
		if err != nil {
			return CreateResult{}, enrollmentField(err)
		}
		request.TokenPurpose = purpose
		request.TokenTTL = ttl
	} else {
		request.TokenPurpose = ""
		request.TokenTTL = 0
	}
	digest, err := digestRequest(struct {
		Name         string `json:"name"`
		Description  string `json:"description"`
		Region       string `json:"region"`
		IPv4         string `json:"ipv4"`
		IPv6         string `json:"ipv6"`
		IssueToken   bool   `json:"issue_enrollment_token"`
		TokenPurpose string `json:"enrollment_purpose"`
		TokenTTL     int64  `json:"enrollment_token_ttl_seconds"`
	}{
		request.Name, request.Description, request.Region, request.IPv4, request.IPv6,
		request.IssueToken, request.TokenPurpose, int64(request.TokenTTL / time.Second),
	})
	if err != nil {
		return CreateResult{}, err
	}

	nodeID, err := newID()
	if err != nil {
		return CreateResult{}, err
	}
	input := createStoreInput{
		ID:             nodeID,
		Actor:          actor,
		Name:           request.Name,
		Description:    request.Description,
		Region:         request.Region,
		IPv4:           request.IPv4,
		IPv6:           request.IPv6,
		RequestID:      request.RequestID,
		IdempotencyKey: request.IdempotencyKey,
		IssueToken:     request.IssueToken,
		TokenPurpose:   request.TokenPurpose,
		TokenTTL:       request.TokenTTL,
	}
	result, err := s.store.Create(ctx, input, digest)
	if err != nil {
		return CreateResult{}, err
	}
	return result, nil
}

func (s *Service) IssueEnrollmentToken(
	ctx context.Context,
	actor Actor,
	nodeID uuid.UUID,
	purpose string,
	ttl time.Duration,
	requestID string,
) (IssuedToken, error) {
	purpose, ttl, err := validateTokenRequest(purpose, ttl)
	if err != nil {
		return IssuedToken{}, err
	}
	metadata, raw, tokenHash, err := newToken(nodeID, purpose, ttl, s.store.now)
	if err != nil {
		return IssuedToken{}, err
	}
	issued, err := s.store.IssueToken(ctx, actor, issueStoreInput{
		Metadata:  metadata,
		TokenHash: tokenHash,
	}, requestID)
	if err != nil {
		return IssuedToken{}, err
	}
	issued.Token = raw
	return issued, nil
}

func (s *Service) ListNodes(ctx context.Context, request ListRequest) (ListResult, error) {
	if request.Limit < 1 || request.Limit > MaxListLimit || (request.State != "" && !validState(request.State)) ||
		request.State == StateRetired {
		return ListResult{}, ErrInvalidInput
	}
	return s.store.List(ctx, request)
}

func (s *Service) GetNode(ctx context.Context, scopeID uuid.UUID, nodeID uuid.UUID) (Node, error) {
	return s.store.Get(ctx, scopeID, nodeID)
}

// NodeIPLocation reads a platform node's IP 归属 (effective, manual fields,
// automatic resolution).
func (s *Service) NodeIPLocation(ctx context.Context, scopeID, nodeID uuid.UUID) (IPLocationView, error) {
	if scopeID == uuid.Nil || nodeID == uuid.Nil {
		return IPLocationView{}, ErrInvalidInput
	}
	return s.store.IPLocation(ctx, scopeID, nodeID)
}

func (s *Service) UpdateNode(ctx context.Context, actor Actor, request UpdateRequest) (WriteResult, error) {
	if !validActor(actor) || request.ID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return WriteResult{}, ErrInvalidInput
	}
	if err := normalizeUpdateFields(&request.Fields); err != nil {
		return WriteResult{}, err
	}
	digest, err := digestRequest(struct {
		ID               uuid.UUID    `json:"id"`
		ExpectedRevision int64        `json:"expected_revision"`
		Fields           UpdateFields `json:"fields"`
	}{request.ID, request.ExpectedRevision, request.Fields})
	if err != nil {
		return WriteResult{}, err
	}
	return s.store.Update(ctx, actor, request, digest)
}

func (s *Service) BatchAdminState(ctx context.Context, actor Actor, request BatchAdminStateRequest) (BatchAdminStateResult, error) {
	request.AdminState = strings.TrimSpace(request.AdminState)
	if !validActor(actor) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) ||
		len(request.Items) < 1 || len(request.Items) > 100 || !validManagedTargetState(request.AdminState) {
		return BatchAdminStateResult{}, ErrInvalidInput
	}
	seen := make(map[uuid.UUID]struct{}, len(request.Items))
	for _, item := range request.Items {
		if item.ID == uuid.Nil || item.ExpectedRevision < 1 {
			return BatchAdminStateResult{}, ErrInvalidInput
		}
		if _, exists := seen[item.ID]; exists {
			return BatchAdminStateResult{}, ErrInvalidInput
		}
		seen[item.ID] = struct{}{}
	}
	digest, err := digestRequest(struct {
		AdminState string                `json:"admin_state"`
		Items      []BatchAdminStateItem `json:"items"`
	}{request.AdminState, request.Items})
	if err != nil {
		return BatchAdminStateResult{}, err
	}
	return s.store.BatchAdminState(ctx, actor, request, digest)
}

func (s *Service) ConsumeEnrollmentToken(ctx context.Context, request ConsumeRequest) (Authorization, error) {
	if request.Token == "" || !validPurpose(request.Purpose) || len(request.RequestID) < 1 || len(request.RequestID) > 128 {
		return Authorization{}, ErrInvalidInput
	}
	return s.store.Consume(ctx, consumeStoreInput{
		TokenHash:     hashToken(request.Token),
		Purpose:       request.Purpose,
		RequestID:     request.RequestID,
		RequestDigest: request.RequestDigest[:],
	})
}

func newToken(nodeID uuid.UUID, purpose string, ttl time.Duration, now func() time.Time) (TokenMetadata, string, []byte, error) {
	tokenID, err := newID()
	if err != nil {
		return TokenMetadata{}, "", nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return TokenMetadata{}, "", nil, err
	}
	raw := base64.RawURLEncoding.EncodeToString(secret)
	issuedAt := now().UTC()
	return TokenMetadata{
		ID:        tokenID,
		NodeID:    nodeID,
		Purpose:   purpose,
		CreatedAt: issuedAt,
		ExpiresAt: issuedAt.Add(ttl),
	}, raw, hashToken(raw), nil
}

func validateTokenRequest(purpose string, ttl time.Duration) (string, time.Duration, error) {
	if purpose == "" {
		purpose = PurposeInitial
	}
	if ttl == 0 {
		ttl = defaultTokenTTL
	}
	if !validPurpose(purpose) {
		return "", 0, errTokenPurpose
	}
	if ttl < minTokenTTL || ttl > maxTokenTTL || ttl%time.Second != 0 {
		return "", 0, ErrInvalidInput
	}
	return purpose, ttl, nil
}

// invalidField is ErrInvalidInput naming the refused node request field
// (fix-fielderr-be); paths follow the create body, the update body
// (UpdateFields) and its management_settings.
func invalidField(field, reason string) error { return fielderr.New(ErrInvalidInput, field, reason) }

func nodeText(field, value string, minimum, maximum int) error {
	count := utf8.RuneCountInString(value)
	switch {
	case count == 0 && minimum > 0:
		return invalidField(field, fielderr.Required)
	case count > maximum:
		return invalidField(field, fielderr.TooLong)
	}
	return nil
}

// nodeIP canonicalizes an optional address of one family.
func nodeIP(field, value string, v4 bool) (string, error) {
	if value == "" {
		return "", nil
	}
	ip := net.ParseIP(value)
	if ip == nil || (ip.To4() != nil) != v4 {
		return "", invalidField(field, fielderr.InvalidFormat)
	}
	return ip.String(), nil
}

// enrollmentField names the create-body token field validateTokenRequest refused.
func enrollmentField(err error) error {
	if errors.Is(err, errTokenPurpose) {
		return invalidField("enrollment_purpose", fielderr.Invalid)
	}
	return invalidField("enrollment_token_ttl_seconds", fielderr.OutOfRange)
}

func normalizeUpdateFields(fields *UpdateFields) error {
	if fields.Name == nil && fields.Description == nil && fields.Region == nil && fields.IPv4 == nil && fields.IPv6 == nil && fields.AdminState == nil && fields.ManagementSettings == nil {
		return ErrInvalidInput
	}
	for _, item := range []struct {
		field            string
		value            **string
		minimum, maximum int
	}{{"name", &fields.Name, 1, 128}, {"description", &fields.Description, 0, 1024}, {"region", &fields.Region, 0, 64}} {
		if *item.value == nil {
			continue
		}
		value := strings.TrimSpace(**item.value)
		if err := nodeText(item.field, value, item.minimum, item.maximum); err != nil {
			return err
		}
		*item.value = &value
	}
	for _, item := range []struct {
		field string
		value **string
		v4    bool
	}{{"ipv4", &fields.IPv4, true}, {"ipv6", &fields.IPv6, false}} {
		if *item.value == nil {
			continue
		}
		value, err := nodeIP(item.field, strings.TrimSpace(**item.value), item.v4)
		if err != nil {
			return err
		}
		*item.value = &value
	}
	if fields.AdminState != nil {
		value := strings.TrimSpace(*fields.AdminState)
		if !validManagedTargetState(value) {
			return invalidField("admin_state", fielderr.Invalid)
		}
		fields.AdminState = &value
	}
	if fields.ManagementSettings != nil {
		if err := normalizeManagementSettings(fields.ManagementSettings); err != nil {
			return fielderr.Within(err, "management_settings")
		}
	}
	return nil
}

func normalizeManagementSettings(settings *NodeManagementSettings) error {
	settings.CacheDirectory = strings.TrimSpace(settings.CacheDirectory)
	settings.LogDirectory = strings.TrimSpace(settings.LogDirectory)
	settings.IPLocation.Country = strings.TrimSpace(settings.IPLocation.Country)
	settings.IPLocation.Province = strings.TrimSpace(settings.IPLocation.Province)
	settings.IPLocation.City = strings.TrimSpace(settings.IPLocation.City)
	settings.IPLocation.ISP = strings.TrimSpace(settings.IPLocation.ISP)
	settings.IPLocation.CountryCode = strings.ToUpper(strings.TrimSpace(settings.IPLocation.CountryCode))
	manual, ok := normalizeIPLocationManual(settings.IPLocationManual)
	if !ok {
		return invalidField("ip_location_manual", fielderr.Invalid)
	}
	settings.IPLocationManual = manual
	settings.AutoDisable.BandwidthUnit = strings.TrimSpace(settings.AutoDisable.BandwidthUnit)
	settings.AutoDisable.TrafficFromTime = strings.TrimSpace(settings.AutoDisable.TrafficFromTime)
	settings.AutoDisable.ExcludedInterfaces = strings.Join(strings.Fields(settings.AutoDisable.ExcludedInterfaces), " ")
	settings.AutoDisable.DisabledPeriods = strings.Join(strings.Fields(settings.AutoDisable.DisabledPeriods), " ")

	auto := settings.AutoDisable
	for _, check := range []struct {
		bad           bool
		field, reason string
	}{
		{settings.SchemaVersion != 1, "schema_version", fielderr.Invalid},
		{settings.Sort < 0 || settings.Sort > 999999, "sort", fielderr.OutOfRange},
		{settings.NodeType != "L1" && settings.NodeType != "L2", "node_type", fielderr.Invalid},
		{!validManagementText(settings.CacheDirectory, 512), "cache_directory", fielderr.InvalidFormat},
		{!validManagementText(settings.LogDirectory, 512), "log_directory", fielderr.InvalidFormat},
		{settings.CacheLimitGB > 1_000_000_000, "cache_limit_gb", fielderr.OutOfRange},
		{!validLocation(settings.IPLocation), "ip_location", fielderr.Invalid},
		{auto.BandwidthLimit > 1_000_000_000, "auto_disable.bandwidth_limit", fielderr.OutOfRange},
		{auto.BandwidthUnit != "Mbps" && auto.BandwidthUnit != "Gbps", "auto_disable.bandwidth_unit", fielderr.Invalid},
		{auto.TrafficTotalGB > 1_000_000_000, "auto_disable.traffic_total_gb", fielderr.OutOfRange},
		{auto.TrafficFromDay < 1 || auto.TrafficFromDay > 28, "auto_disable.traffic_from_day", fielderr.OutOfRange},
		{!timeOfDayPattern.MatchString(auto.TrafficFromTime), "auto_disable.traffic_from_time", fielderr.InvalidFormat},
		{!validTrafficTypes(auto.TrafficTypes), "auto_disable.traffic_types", fielderr.Invalid},
		{!validInterfaces(auto.ExcludedInterfaces), "auto_disable.excluded_interfaces", fielderr.InvalidFormat},
		{!validDisabledPeriods(auto.DisabledPeriods), "auto_disable.disabled_periods", fielderr.InvalidFormat},
		{len(settings.SecondaryIPs) > 64, "secondary_ips", fielderr.TooLong},
	} {
		if check.bad {
			return invalidField(check.field, check.reason)
		}
	}
	seen := make(map[string]struct{}, len(settings.SecondaryIPs))
	for index, value := range settings.SecondaryIPs {
		field := "secondary_ips[" + strconv.Itoa(index) + "]"
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			return invalidField(field, fielderr.InvalidFormat)
		}
		canonical := ip.String()
		if _, exists := seen[canonical]; exists {
			return invalidField(field, fielderr.Duplicate)
		}
		seen[canonical] = struct{}{}
		settings.SecondaryIPs[index] = canonical
	}
	if settings.SecondaryIPs == nil {
		settings.SecondaryIPs = []string{}
	}
	settings.Schedule302Hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(settings.Schedule302Hostname), "."))
	if settings.Schedule302Hostname != "" && (!sched302.ValidHostname(settings.Schedule302Hostname) ||
		len(settings.Schedule302Hostname) < 4) {
		return invalidField("schedule302_hostname", fielderr.InvalidFormat)
	}
	return nil
}

func validManagementText(value string, maximum int) bool {
	return utf8.RuneCountInString(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func validLocation(value NodeIPLocation) bool {
	for _, field := range []string{value.Country, value.Province, value.City, value.ISP} {
		if !validManagementText(field, 128) {
			return false
		}
	}
	return value.CountryCode == "" || countryCodePattern.MatchString(value.CountryCode)
}

func validTrafficTypes(values []string) bool {
	if len(values) < 1 || len(values) > 2 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if (value != "outbound" && value != "inbound") || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validInterfaces(value string) bool {
	for _, name := range strings.Fields(value) {
		if !interfacePattern.MatchString(name) {
			return false
		}
	}
	return utf8.RuneCountInString(value) <= 512
}

func validDisabledPeriods(value string) bool {
	if utf8.RuneCountInString(value) > 1024 {
		return false
	}
	for _, period := range strings.Fields(value) {
		parts := strings.Split(period, "-")
		if len(parts) != 2 || !timeOfDayPattern.MatchString(parts[0]) || !timeOfDayPattern.MatchString(parts[1]) || parts[0] == parts[1] {
			return false
		}
	}
	return true
}

func validManagedTargetState(state string) bool {
	return state == StateActive || state == StateDraining || state == StateDisabled || state == StateRetired
}

func validateStateChange(current, target string, hasAuthorization bool) error {
	// "retired" as a target means delete: any node can be deleted, including
	// a legacy retired row left by releases before physical deletion.
	if target == StateRetired {
		return nil
	}
	if current == StateRetired {
		return ErrRetired
	}
	if target == "" || target == current {
		return nil
	}
	switch current {
	case StatePending:
		// "Initialize": only a host that completed enrollment and still holds
		// a live certificate may start serving (hasAuthorization carries that
		// fact for pending nodes, see initializationEvidence).
		if target == StateActive {
			if !hasAuthorization {
				return ErrIdentityRequired
			}
			return nil
		}
	case StateActive:
		if target == StateDraining || target == StateDisabled {
			return nil
		}
	case StateDraining:
		if target == StateDisabled {
			return nil
		}
		if target == StateActive {
			if !hasAuthorization {
				return ErrIdentityRequired
			}
			return nil
		}
	case StateDisabled:
		if target == StateActive {
			if !hasAuthorization {
				return ErrIdentityRequired
			}
			return nil
		}
	}
	return ErrStateTransition
}

// errTokenPurpose is ErrInvalidInput for an unknown enrollment purpose.
var errTokenPurpose = fmt.Errorf("%w: enrollment purpose", ErrInvalidInput)

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil
}

func validWriteMetadata(key, requestID string) bool {
	return writeMetadataPattern.MatchString(key) && writeMetadataPattern.MatchString(requestID)
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validPurpose(purpose string) bool {
	return purpose == PurposeInitial || purpose == PurposeReEnrollment
}

func validState(state string) bool {
	switch state {
	case StatePending, StateActive, StateDraining, StateDisabled, StateRetired:
		return true
	default:
		return false
	}
}

func hashToken(raw string) []byte {
	digest := sha256.Sum256([]byte(raw))
	return digest[:]
}

func newID() (uuid.UUID, error) {
	return uuid.NewV7()
}
