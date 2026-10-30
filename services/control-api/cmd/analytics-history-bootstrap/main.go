package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

var (
	errInvalidConfig = errors.New("analytics history bootstrap configuration is invalid")
	errUnsafeBroker  = errors.New("analytics history bootstrap broker state is not pristine")
	errInstallDrift  = errors.New("analytics history bootstrap installation identity does not match")
	errHistoryDrift  = errors.New("analytics history bootstrap generation does not match broker identity")
)

type bootstrapConfig struct {
	DatabaseURL      string
	InstallationID   string
	NATSURL          string
	NATSUsername     string
	NATSPassword     string
	Stream           string
	Durable          string
	ConnectTimeout   time.Duration
	OperationTimeout time.Duration
	CAFile           string
}

type bootstrapGeneration struct {
	Generation     analytics.IngestHistoryGenerationV1
	HistoryStartAt time.Time
	CreatedAt      time.Time
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	config, err := loadBootstrapConfig(os.LookupEnv)
	if err == nil {
		err = runBootstrap(ctx, config)
	}
	if err != nil {
		slog.Error("analytics history bootstrap failed", "error", err)
		os.Exit(1)
	}
	slog.Info("analytics history bootstrap verified")
}

func loadBootstrapConfig(lookup func(string) (string, bool)) (bootstrapConfig, error) {
	if lookup == nil {
		return bootstrapConfig{}, errInvalidConfig
	}
	value := func(name string) string {
		result, _ := lookup(name)
		return strings.TrimSpace(result)
	}
	config := bootstrapConfig{
		DatabaseURL: value("DATABASE_URL"), InstallationID: value("CONTROL_INSTALLATION_ID"),
		NATSURL: value("ANALYTICS_INGEST_NATS_URL"), NATSUsername: value("ANALYTICS_INGEST_NATS_USER"),
		NATSPassword: value("ANALYTICS_INGEST_NATS_PASSWORD"), CAFile: value("SSL_CERT_FILE"),
		Stream: value("ANALYTICS_INGEST_STREAM"), Durable: value("ANALYTICS_INGEST_DURABLE"),
	}
	if config.Stream == "" {
		config.Stream = "ANALYTICS_INGEST_V1"
	}
	if config.Durable == "" {
		config.Durable = "control_api_analytics_ingest_v1"
	}
	var err error
	if config.ConnectTimeout, err = bootstrapDuration(value("ANALYTICS_INGEST_CONNECT_TIMEOUT"), 3*time.Second); err != nil {
		return bootstrapConfig{}, errInvalidConfig
	}
	if config.OperationTimeout, err = bootstrapDuration(value("ANALYTICS_INGEST_OPERATION_TIMEOUT"), 5*time.Second); err != nil {
		return bootstrapConfig{}, errInvalidConfig
	}
	if config.DatabaseURL == "" || config.InstallationID == "" ||
		(config.NATSUsername == "") != (config.NATSPassword == "") || !validNATSURL(config.NATSURL) {
		return bootstrapConfig{}, errInvalidConfig
	}
	if config.NATSUsername == "" {
		endpoint, _ := url.Parse(config.NATSURL)
		host := endpoint.Hostname()
		if endpoint.Scheme != "nats" || !(strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()) {
			return bootstrapConfig{}, errInvalidConfig
		}
	}
	if strings.HasPrefix(config.NATSURL, "tls://") && config.CAFile != "" {
		if _, err := os.Stat(config.CAFile); err != nil {
			return bootstrapConfig{}, errInvalidConfig
		}
	}
	return config, nil
}

func bootstrapDuration(value string, fallback time.Duration) (time.Duration, error) {
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < 100*time.Millisecond || parsed > 30*time.Second {
		return 0, errInvalidConfig
	}
	return parsed, nil
}

func validNATSURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "tls" {
		return true
	}
	if parsed.Scheme != "nats" {
		return false
	}
	host := parsed.Hostname()
	// Allow localhost, loopback IPs, and Docker service names for local development
	if strings.EqualFold(host, "localhost") || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return true
	}
	// Allow common Docker service names for local development.
	return host == "nats" || host == "nats-server"
}

func runBootstrap(ctx context.Context, config bootstrapConfig) error {
	pool, err := pgxpool.New(ctx, config.DatabaseURL)
	if err != nil {
		return errors.New("open analytics history bootstrap database")
	}
	defer pool.Close()
	operationCtx, cancel := context.WithTimeout(ctx, config.OperationTimeout)
	err = pool.Ping(operationCtx)
	cancel()
	if err != nil {
		return errors.New("verify analytics history bootstrap database")
	}

	options := []nats.Option{
		nats.Name("cdnca-analytics-history-bootstrap"), nats.Timeout(config.ConnectTimeout),
		nats.NoReconnect(), nats.NoCallbacksAfterClientClose(),
	}
	if config.NATSUsername != "" {
		options = append(options, nats.UserInfo(config.NATSUsername, config.NATSPassword))
	}
	if strings.HasPrefix(config.NATSURL, "tls://") {
		options = append(options, nats.TLSHandshakeFirst())
		if config.CAFile != "" {
			options = append(options, nats.RootCAs(config.CAFile))
		}
	}
	connection, err := nats.Connect(config.NATSURL, options...)
	if err != nil {
		return errors.New("connect analytics history bootstrap NATS")
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(config.OperationTimeout))
	if err != nil {
		return errors.New("open analytics history bootstrap JetStream")
	}
	operationCtx, cancel = context.WithTimeout(ctx, config.OperationTimeout)
	stream, streamErr := jetstream.StreamInfo(config.Stream, nats.Context(operationCtx))
	consumer, consumerErr := jetstream.ConsumerInfo(config.Stream, config.Durable, nats.Context(operationCtx))
	cancel()
	if streamErr != nil || consumerErr != nil {
		return errors.New("inspect analytics history bootstrap broker identity")
	}
	bootstrap, err := generationFromBroker(config, stream, consumer, time.Now())
	if err != nil {
		return err
	}
	operationCtx, cancel = context.WithTimeout(ctx, config.OperationTimeout)
	err = persistGeneration(operationCtx, pool, bootstrap)
	cancel()
	return err
}

func generationFromBroker(
	config bootstrapConfig,
	stream *nats.StreamInfo,
	consumer *nats.ConsumerInfo,
	now time.Time,
) (bootstrapGeneration, error) {
	if stream == nil || consumer == nil || stream.Config.Name != config.Stream || consumer.Stream != config.Stream ||
		consumer.Name != config.Durable || consumer.Config.Durable != config.Durable ||
		consumer.Config.DeliverPolicy != nats.DeliverAllPolicy || consumer.Config.AckPolicy != nats.AckExplicitPolicy ||
		consumer.Config.FilterSubject != analytics.IngestSubjectPrefix+".*" || stream.State.Consumers != 1 ||
		stream.State.FirstSeq > 1 || stream.State.NumDeleted != 0 || len(stream.State.Deleted) != 0 ||
		(stream.State.FirstSeq == 0 && (stream.State.Msgs != 0 || stream.State.LastSeq != 0)) ||
		consumer.Delivered.Consumer != 0 || consumer.Delivered.Stream != 0 ||
		consumer.AckFloor.Consumer != 0 || consumer.AckFloor.Stream != 0 ||
		consumer.NumAckPending != 0 || consumer.NumRedelivered != 0 || consumer.NumPending != stream.State.Msgs {
		return bootstrapGeneration{}, errUnsafeBroker
	}
	streamCreated, consumerCreated := stream.Created.UTC(), consumer.Created.UTC()
	if streamCreated.IsZero() || consumerCreated.IsZero() || streamCreated.UnixNano() <= 0 ||
		consumerCreated.UnixNano() < streamCreated.UnixNano() {
		return bootstrapGeneration{}, errUnsafeBroker
	}
	createdAt := now.UTC()
	if createdAt.Before(consumerCreated) {
		createdAt = consumerCreated
	}
	result := bootstrapGeneration{
		Generation: analytics.IngestHistoryGenerationV1{
			InstallationID: config.InstallationID, StreamName: config.Stream, DurableName: config.Durable,
			StreamCreatedUnixNano: uint64(streamCreated.UnixNano()), ConsumerCreatedUnixNano: uint64(consumerCreated.UnixNano()),
			HistoryEpoch: uuid.NewString(), HistoryStartSequence: 1,
		},
		HistoryStartAt: consumerCreated, CreatedAt: createdAt,
	}
	if analytics.ValidateIngestHistoryGenerationV1(result.Generation) != nil {
		return bootstrapGeneration{}, errInvalidConfig
	}
	return result, nil
}

func persistGeneration(ctx context.Context, pool *pgxpool.Pool, bootstrap bootstrapGeneration) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return errors.New("begin analytics history bootstrap transaction")
	}
	defer tx.Rollback(ctx)
	generation := bootstrap.Generation
	if _, err := tx.Exec(ctx, `INSERT INTO control_installation_entitlement(singleton,installation_id)
		VALUES(true,$1) ON CONFLICT(singleton) DO NOTHING`, generation.InstallationID); err != nil {
		return errors.New("create analytics history bootstrap installation identity")
	}
	var installationID string
	if err := tx.QueryRow(ctx, `SELECT installation_id FROM control_installation_entitlement
		WHERE singleton=true FOR UPDATE`).Scan(&installationID); err != nil || installationID != generation.InstallationID {
		return errInstallDrift
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
		$1 || chr(31) || $2 || chr(31) || $3 || chr(31) || $4,83))`,
		generation.InstallationID, generation.NATSDomain, generation.StreamName, generation.DurableName); err != nil {
		return errors.New("lock analytics history bootstrap identity")
	}
	rows, err := tx.Query(ctx, `SELECT stream_created_unix_nano::text,consumer_created_unix_nano::text,
		history_epoch::text,history_start_sequence::text FROM analytics_history_streams
		WHERE installation_id=$1 AND nats_domain=$2 AND stream_name=$3 AND durable_name=$4
		AND retired_at IS NULL LIMIT 2`, generation.InstallationID, generation.NATSDomain,
		generation.StreamName, generation.DurableName)
	if err != nil {
		return errors.New("inspect analytics history bootstrap generation")
	}
	count := 0
	var existing analytics.IngestHistoryGenerationV1
	for rows.Next() {
		count++
		var streamCreated, consumerCreated, historyStart string
		if err := rows.Scan(&streamCreated, &consumerCreated, &existing.HistoryEpoch, &historyStart); err != nil {
			rows.Close()
			return errors.New("inspect analytics history bootstrap generation")
		}
		existing.InstallationID, existing.NATSDomain = generation.InstallationID, generation.NATSDomain
		existing.StreamName, existing.DurableName = generation.StreamName, generation.DurableName
		existing.StreamCreatedUnixNano, _ = strconv.ParseUint(streamCreated, 10, 64)
		existing.ConsumerCreatedUnixNano, _ = strconv.ParseUint(consumerCreated, 10, 64)
		existing.HistoryStartSequence, _ = strconv.ParseUint(historyStart, 10, 64)
	}
	rows.Close()
	if count > 1 || count == 1 && (analytics.ValidateIngestHistoryGenerationV1(existing) != nil ||
		existing.StreamCreatedUnixNano != generation.StreamCreatedUnixNano ||
		existing.ConsumerCreatedUnixNano != generation.ConsumerCreatedUnixNano || existing.HistoryStartSequence != 1) {
		return errHistoryDrift
	}
	if count == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO analytics_history_streams(
			installation_id,nats_domain,stream_name,durable_name,
			stream_created_unix_nano,consumer_created_unix_nano,history_epoch,
			history_start_sequence,history_start_at,legacy_baseline_kind,
			broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor,
			revision,last_reconciled_at,created_at,updated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,'none',0,0,0,1,$9,$9,$9)`,
			generation.InstallationID, generation.NATSDomain, generation.StreamName, generation.DurableName,
			generation.StreamCreatedUnixNano, generation.ConsumerCreatedUnixNano, generation.HistoryEpoch,
			bootstrap.HistoryStartAt, bootstrap.CreatedAt)
		if err != nil {
			return errors.New("create analytics history bootstrap generation")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("commit analytics history bootstrap generation")
	}
	return nil
}
