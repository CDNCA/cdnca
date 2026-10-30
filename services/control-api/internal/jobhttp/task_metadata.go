package jobhttp

import "github.com/google/uuid"

type TaskName struct {
	NameKey  string `json:"name_key"`
	Resource string `json:"resource"`
	Source   string `json:"source"`
}

type TaskPriority struct {
	Policy string `json:"policy"`
}

type TaskDependency struct {
	TaskID   uuid.UUID `json:"task_id"`
	Relation string    `json:"relation"`
	Status   State     `json:"status"`
}

type TaskDependencies struct {
	State string           `json:"state"`
	Items []TaskDependency `json:"items"`
}

type TaskMetadata struct {
	TaskID       uuid.UUID        `json:"task_id"`
	Name         TaskName         `json:"name"`
	Priority     TaskPriority     `json:"priority"`
	Dependencies TaskDependencies `json:"dependencies"`
}

func derivedTaskMetadata(job Job) TaskMetadata {
	nameKey := "jobs.kindNames.unknown"
	// Only dns.cname.allocation has a recorded dependency relation; other
	// integrated kinds have no dependency concept, so "none" is a fact.
	dependencyState := "unknown"
	for _, kind := range integratedKinds {
		if kind.Kind == job.Kind {
			nameKey = kind.NameKey
			if kind.Kind != "dns.cname.allocation" {
				dependencyState = "none"
			}
			break
		}
	}
	policy := "unknown"
	switch job.Kind {
	case "dns_reconcile", "dns.cname.allocation", "dns.cname.intent", "dns.cname.stream_intent", "package.monitor.evaluate.v1", "site.status_recovery":
		policy = "ready_fifo"
	case "cache.operation", "analytics.log_export", "edge.publication":
		policy = "producer_managed"
	}
	return TaskMetadata{
		TaskID:       job.TaskID,
		Name:         TaskName{NameKey: nameKey, Resource: job.RelatedResource.Reference, Source: "derived"},
		Priority:     TaskPriority{Policy: policy},
		Dependencies: TaskDependencies{State: dependencyState, Items: []TaskDependency{}},
	}
}

func metadataForJobs(jobs []Job) ([]TaskMetadata, error) {
	result := make([]TaskMetadata, len(jobs))
	for index, job := range jobs {
		metadata := derivedTaskMetadata(job)
		if job.taskMetadata != nil {
			metadata = *job.taskMetadata
		}
		expected := derivedTaskMetadata(job)
		if metadata.TaskID != job.TaskID || metadata.Name != expected.Name || metadata.Priority != expected.Priority {
			return nil, ErrInvalidStoreResponse
		}
		dependencies := metadata.Dependencies
		if dependencies.State != "unknown" && dependencies.State != "observed" && dependencies.State != "none" ||
			dependencies.Items == nil ||
			dependencies.State != "observed" && len(dependencies.Items) != 0 ||
			dependencies.State == "none" && expected.Dependencies.State != "none" ||
			dependencies.State == "observed" && (job.Kind != "dns.cname.allocation" || len(dependencies.Items) != 1) {
			return nil, ErrInvalidStoreResponse
		}
		for _, dependency := range dependencies.Items {
			if dependency.TaskID == uuid.Nil || dependency.TaskID == job.TaskID ||
				dependency.Relation != "completion" || !validState(dependency.Status) {
				return nil, ErrInvalidStoreResponse
			}
		}
		result[index] = metadata
	}
	return result, nil
}
