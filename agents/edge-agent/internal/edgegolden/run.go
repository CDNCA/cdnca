package edgegolden

import (
	"context"
	"crypto/x509"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"
)

// logSettle is how long a logs step waits for the runtime to finish writing
// the lines of requests that already completed.
const logSettle = 500 * time.Millisecond

// ErrSkipped reports a scenario the environment cannot run (Requires).
type ErrSkipped struct{ Missing []string }

func (err ErrSkipped) Error() string {
	return fmt.Sprintf("skipped: environment lacks %v", err.Missing)
}

// Run starts the scenario's origins and the renderer's runtime, runs every
// step and returns the normalized observation.
func Run(ctx context.Context, renderer Renderer, env Env, scenario *Scenario) (*Observation, error) {
	var missing []string
	for _, name := range scenario.Requires {
		if !env.Provides(name) {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return nil, ErrSkipped{Missing: missing}
	}
	record := &recorder{}
	origins, err := startOrigins(scenario, env.PKI, record)
	if err != nil {
		return nil, err
	}
	defer origins.close()
	instance, err := renderer.Start(ctx, env, scenario)
	if err != nil {
		return nil, fmt.Errorf("start %s: %w", renderer.Name(), err)
	}
	defer func() { _ = instance.Stop(context.WithoutCancel(ctx)) }()
	// Anything the start-up sent to the origins is not part of a step.
	record.drain()

	roots := x509.NewCertPool()
	roots.AddCert(env.PKI.CAs["site"].Certificate)
	observation := &Observation{Schema: ObservationSchema, Scenario: scenario.Name, Digest: scenario.Digest()}
	named := &connections{}
	defer named.close()
	for _, step := range scenario.Steps {
		if step.ClientCert != "" {
			ca, err := env.PKI.CA(step.ClientCert)
			if err != nil {
				return nil, fmt.Errorf("step %s: %w", step.ID, err)
			}
			// The subject is fixed so observations do not depend on the run.
			certificate, err := ca.ClientCertificate(1000, "golden client")
			if err != nil {
				return nil, fmt.Errorf("step %s: %w", step.ID, err)
			}
			step.clientCertificate = &certificate
		}
		result, err := runStep(ctx, env, instance, named, scenario, step, roots, record)
		if err != nil {
			return nil, fmt.Errorf("step %s: %w", step.ID, err)
		}
		observation.Steps = append(observation.Steps, result)
	}
	return observation, nil
}

func runStep(ctx context.Context, env Env, instance Instance, named *connections, scenario *Scenario, step Step, roots *x509.CertPool,
	record *recorder) (StepResult, error) {
	result := StepResult{ID: step.ID, Kind: step.Kind}
	switch step.Kind {
	case "http":
		count := max(step.Repeat, 1)
		if step.Concurrent {
			responses := make([]Response, count)
			var wait sync.WaitGroup
			for index := range responses {
				wait.Add(1)
				go func() {
					defer wait.Done()
					responses[index] = sendHTTP(ctx, step, roots, scenario.Mask)
				}()
			}
			wait.Wait()
			result.Summary = summarize(responses, record.drain())
			return result, nil
		}
		var responses []Response
		var origin []OriginRequest
		for range count {
			var response Response
			switch {
			case step.Proto == "h3":
				response = sendHTTP3(ctx, env, step, scenario.Mask)
			case step.Connection != "":
				response = named.send(ctx, step, roots, scenario.Mask)
			default:
				response = sendHTTP(ctx, step, roots, scenario.Mask)
			}
			if step.FollowLocation && response.Status >= 300 && response.Status < 400 {
				response.Followed = followLocation(ctx, step, response.location, roots, scenario.Mask)
			}
			response.Origin = record.drain()
			origin = append(origin, response.Origin...)
			responses = append(responses, response)
		}
		if step.Summary {
			result.Summary = summarize(responses, origin)
		} else {
			result.Responses = responses
		}
	case "tls":
		result.TLS = handshake(ctx, step, roots)
		record.drain()
	case "tcp", "udp":
		result.Stream = streamExchange(ctx, step, roots)
		record.drain()
	case "publish":
		if err := instance.Publish(ctx, *step.Publish); err != nil {
			return result, fmt.Errorf("publish: %w", err)
		}
		record.drain()
	case "websocket":
		result.WebSocket = websocketExchange(ctx, step)
		result.WebSocket.Origin = record.drain()
	case "task":
		task, err := instance.Task(ctx, *step.Task)
		if err != nil {
			task = &TaskResult{Error: err.Error()}
		}
		task.Origin = record.drain()
		result.Task = task
	case "logs":
		time.Sleep(logSettle)
		records, err := instance.Logs(ctx)
		if err != nil {
			return result, err
		}
		for index := range records {
			records[index].Fields = maskLogFields(scenario.Mask, records[index].Fields)
		}
		if records == nil {
			records = []LogRecord{}
		}
		result.Logs = records
	case "cache_entries":
		keys, err := instance.CacheEntries(ctx, step.SiteID)
		if err != nil {
			return result, err
		}
		sort.Strings(keys)
		if keys == nil {
			keys = []string{}
		}
		result.Cache = &CacheEntries{Count: len(keys), Keys: keys}
	case "sleep":
		time.Sleep(time.Duration(step.DelayMS) * time.Millisecond)
	}
	return result, nil
}

// summarize keeps what is stable when the order or the chosen origin of
// individual responses is not (random choice, concurrent requests).
func summarize(responses []Response, origin []OriginRequest) *RepeatSummary {
	summary := &RepeatSummary{Count: len(responses), Statuses: map[string]int{}, Origins: []string{}, OriginRequests: len(origin)}
	for _, response := range responses {
		if response.Error != "" {
			if summary.Errors == nil {
				summary.Errors = map[string]int{}
			}
			summary.Errors[response.Error]++
		}
		if response.Status != 0 {
			summary.Statuses[strconv.Itoa(response.Status)]++
		}
	}
	seen := map[string]bool{}
	for _, request := range origin {
		if !seen[request.Origin] {
			seen[request.Origin] = true
			summary.Origins = append(summary.Origins, request.Origin)
		}
	}
	sort.Strings(summary.Origins)
	return summary
}

func maskLogFields(mask Mask, fields map[string]any) map[string]any {
	result := make(map[string]any, len(fields))
	for key, value := range fields {
		if contains(mask.LogFields, key) {
			result[key] = "<masked>"
			continue
		}
		if text, ok := value.(string); ok {
			value, _ = mask.text(text)
		}
		result[key] = value
	}
	return result
}
