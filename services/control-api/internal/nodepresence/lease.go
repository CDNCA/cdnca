package nodepresence

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var putLeaseScript = redis.NewScript(`
local function compare_decimal(left, right)
  if string.len(left) < string.len(right) then return -1 end
  if string.len(left) > string.len(right) then return 1 end
  if left < right then return -1 end
  if left > right then return 1 end
  return 0
end

local redis_time = redis.call('TIME')
local now_millis = redis_time[1] .. string.format('%03d', math.floor(redis_time[2] / 1000))
if compare_decimal(ARGV[5], now_millis) <= 0 then return -1 end

local current_epoch = redis.call('HGET', KEYS[1], 'session_epoch')
if current_epoch then
  local epoch_comparison = compare_decimal(current_epoch, ARGV[1])
  if epoch_comparison > 0 then return 0 end
  if epoch_comparison == 0 then
    local current_sequence = redis.call('HGET', KEYS[1], 'heartbeat_sequence')
    if compare_decimal(current_sequence, ARGV[2]) > 0 then return 0 end
  end
end

redis.call('HSET', KEYS[1],
  'schema_version', '1',
  'session_epoch', ARGV[1],
  'heartbeat_sequence', ARGV[2],
  'event_id', ARGV[3],
  'last_seen_unix_millis', ARGV[4])
redis.call('PEXPIREAT', KEYS[1], ARGV[5])
return 1
`)

type RedisLeaseStore struct {
	client           redis.UniversalClient
	keyPrefix        string
	operationTimeout time.Duration
}

func NewRedisLeaseStore(client redis.UniversalClient, keyPrefix string, operationTimeout time.Duration) (*RedisLeaseStore, error) {
	if client == nil || !validRedisKeyPrefix(keyPrefix) || operationTimeout <= 0 {
		return nil, fmt.Errorf("invalid Redis node presence lease configuration")
	}
	return &RedisLeaseStore{client: client, keyPrefix: keyPrefix, operationTimeout: operationTimeout}, nil
}

func (s *RedisLeaseStore) Put(ctx context.Context, lease LeaseRecord) error {
	if lease.NodeID == uuid.Nil || lease.SessionEpoch <= 0 || lease.HeartbeatSequence <= 0 ||
		lease.EventID == uuid.Nil || !lease.ExpiresAt.After(lease.LastSeenAt) {
		return fmt.Errorf("invalid node presence lease")
	}
	operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	result, err := putLeaseScript.Run(operationCtx, s.client, []string{s.key(lease.NodeID)},
		strconv.FormatInt(lease.SessionEpoch, 10),
		strconv.FormatInt(lease.HeartbeatSequence, 10),
		lease.EventID.String(),
		strconv.FormatInt(lease.LastSeenAt.UnixMilli(), 10),
		strconv.FormatInt(lease.ExpiresAt.UnixMilli(), 10),
	).Result()
	if err != nil {
		return fmt.Errorf("write node presence lease: %w", err)
	}
	code, ok := result.(int64)
	if !ok {
		return fmt.Errorf("write node presence lease: unexpected script result")
	}
	if code < 0 {
		return ErrLeaseExpired
	}
	return nil
}

func (s *RedisLeaseStore) Exists(ctx context.Context, nodeID uuid.UUID) (bool, error) {
	if nodeID == uuid.Nil {
		return false, fmt.Errorf("node ID is required")
	}
	operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	count, err := s.client.Exists(operationCtx, s.key(nodeID)).Result()
	if err != nil {
		return false, fmt.Errorf("read node presence lease: %w", err)
	}
	return count == 1, nil
}

func (s *RedisLeaseStore) Signals(ctx context.Context, nodeIDs []uuid.UUID) (map[uuid.UUID]bool, error) {
	result := make(map[uuid.UUID]bool, len(nodeIDs))
	if len(nodeIDs) == 0 {
		return result, nil
	}
	operationCtx, cancel := context.WithTimeout(ctx, s.operationTimeout)
	defer cancel()
	commands := make(map[uuid.UUID]*redis.IntCmd, len(nodeIDs))
	_, err := s.client.Pipelined(operationCtx, func(pipe redis.Pipeliner) error {
		for _, nodeID := range nodeIDs {
			if nodeID == uuid.Nil {
				return fmt.Errorf("node ID is required")
			}
			commands[nodeID] = pipe.Exists(operationCtx, s.key(nodeID))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read node presence lease signals: %w", err)
	}
	for nodeID, command := range commands {
		count, err := command.Result()
		if err != nil {
			return nil, fmt.Errorf("read node presence lease signal: %w", err)
		}
		result[nodeID] = count == 1
	}
	return result, nil
}

func (s *RedisLeaseStore) key(nodeID uuid.UUID) string {
	return s.keyPrefix + ":{" + nodeID.String() + "}:online"
}

func validRedisKeyPrefix(value string) bool {
	if value == "" || strings.HasSuffix(value, ":") {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == ':' || char == '-' || char == '_' {
			continue
		}
		return false
	}
	return true
}
