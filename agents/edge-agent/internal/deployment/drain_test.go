package deployment

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type generationTestRuntime struct {
	*fakeRuntime
	muGeneration sync.Mutex
	generation   RuntimeGeneration
	remaining    int
	events       []string
}

func (runtime *generationTestRuntime) Reload(ctx context.Context, versionID, currentPath string) error {
	runtime.muGeneration.Lock()
	runtime.events = append(runtime.events, "reload:"+versionID)
	runtime.muGeneration.Unlock()
	return runtime.fakeRuntime.Reload(ctx, versionID, currentPath)
}

func (runtime *generationTestRuntime) CaptureGeneration(context.Context) (RuntimeGeneration, error) {
	runtime.muGeneration.Lock()
	defer runtime.muGeneration.Unlock()
	runtime.events = append(runtime.events, "capture")
	return runtime.generation, nil
}

func (runtime *generationTestRuntime) RemainingGeneration(context.Context, RuntimeGeneration) (int, error) {
	runtime.muGeneration.Lock()
	defer runtime.muGeneration.Unlock()
	return runtime.remaining, nil
}

func (runtime *generationTestRuntime) setRemaining(remaining int) {
	runtime.muGeneration.Lock()
	runtime.remaining = remaining
	runtime.muGeneration.Unlock()
}

func TestFormalDeploymentDrainPersistsCapturedGenerationAndResumes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	t.Cleanup(func() { makeTreeWritable(root) })
	runtime := &generationTestRuntime{
		fakeRuntime: &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}},
		generation:  testRuntimeGeneration(), remaining: 1,
	}
	manager, err := NewManager(root, &fakePrechecker{failFor: map[string]error{}}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ConfigureGenerationRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	v1 := testCommand(t, "deploy-v1", 1, "cfg-v1", "", map[string][]byte{"nginx.conf": []byte("v1")})
	if result, err := manager.Process(t.Context(), v1); err != nil || result.State != StateHealthy {
		t.Fatalf("deploy v1 = (%+v, %v)", result, err)
	}
	v2 := testCommand(t, "deploy-v2", 1, "cfg-v2", "cfg-v1", map[string][]byte{"nginx.conf": []byte("v2")})
	if result, err := manager.Process(t.Context(), v2); err != nil || result.State != StateHealthy {
		t.Fatalf("deploy v2 = (%+v, %v)", result, err)
	}
	if got := strings.Join(runtime.events, ","); got != "reload:cfg-v1,capture,reload:cfg-v2" {
		t.Fatalf("runtime order = %q", got)
	}

	request := DrainRequest{
		DeploymentID: "deploy-v2", Revision: 1, Digest: strings.Repeat("a", 64),
		OldVersionID: "cfg-v1", NewVersionID: "cfg-v2", MaxDrain: time.Minute,
		CommandDeadline: time.Now().Add(time.Hour),
	}
	result, err := manager.ProcessDrain(t.Context(), request)
	if !errors.Is(err, ErrDrainInProgress) || result.Phase != DrainPhaseDrainingOld || result.RemainingOldWorkers != 1 {
		t.Fatalf("initial drain = (%+v, %v)", result, err)
	}

	runtime.setRemaining(0)
	restarted, err := NewManager(root, &fakePrechecker{failFor: map[string]error{}}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ConfigureGenerationRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	result, err = restarted.ProcessDrain(t.Context(), request)
	if err != nil || result.Phase != DrainPhaseCompleted || result.RemainingOldWorkers != 0 {
		t.Fatalf("resumed drain = (%+v, %v)", result, err)
	}
	if len(result.Transitions) != 3 || result.Transitions[2].Phase != DrainPhaseCompleted {
		t.Fatalf("drain transitions = %+v", result.Transitions)
	}
}

func TestFormalDeploymentDrainDeadlineDoesNotTerminateOldWorkers(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	t.Cleanup(func() { makeTreeWritable(root) })
	runtime := &generationTestRuntime{
		fakeRuntime: &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}},
		generation:  testRuntimeGeneration(), remaining: 1,
	}
	manager, err := NewManager(root, &fakePrechecker{failFor: map[string]error{}}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ConfigureGenerationRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC) }
	if _, err := manager.Process(t.Context(), testCommand(t, "seed", 1, "cfg-v1", "", map[string][]byte{"nginx.conf": []byte("v1")})); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Process(t.Context(), testCommand(t, "drain-deadline", 1, "cfg-v2", "cfg-v1", map[string][]byte{"nginx.conf": []byte("v2")})); err != nil {
		t.Fatal(err)
	}
	request := DrainRequest{DeploymentID: "drain-deadline", Revision: 1, Digest: strings.Repeat("b", 64),
		OldVersionID: "cfg-v1", NewVersionID: "cfg-v2", MaxDrain: time.Second,
		CommandDeadline: manager.now().Add(time.Minute)}
	if _, err := manager.ProcessDrain(t.Context(), request); !errors.Is(err, ErrDrainInProgress) {
		t.Fatalf("initial ProcessDrain() error = %v", err)
	}
	manager.now = func() time.Time { return time.Date(2026, 8, 7, 0, 0, 2, 0, time.UTC) }
	result, err := manager.ProcessDrain(t.Context(), request)
	if !errors.Is(err, ErrDrainDeadline) || result.Phase != DrainPhaseFailed || result.RemainingOldWorkers != 1 {
		t.Fatalf("deadline drain = (%+v, %v)", result, err)
	}
}

func testRuntimeGeneration() RuntimeGeneration {
	master := ProcessIdentity{PID: 100, ParentPID: 1, Role: "master", StartTicks: 10, ExecutableDevice: 20, ExecutableInode: 30, OwnerUID: 0, BootID: "boot-id"}
	return RuntimeGeneration{Master: master, Workers: []ProcessIdentity{
		{PID: 101, ParentPID: master.PID, Role: "worker", StartTicks: 11, ExecutableDevice: master.ExecutableDevice, ExecutableInode: master.ExecutableInode, OwnerUID: 65534, BootID: master.BootID},
	}}
}

func TestRuntimeGenerationWorkerOwnership(t *testing.T) {
	generation := testRuntimeGeneration()
	if !validRuntimeGeneration(generation) {
		t.Fatal("root OpenResty master must be allowed to drop worker privileges")
	}
	generation.Workers = append(generation.Workers, generation.Workers[0])
	generation.Workers[1].PID++
	generation.Workers[1].StartTicks++
	generation.Workers[1].OwnerUID = 1000
	if validRuntimeGeneration(generation) {
		t.Fatal("workers from one master must have one stable owner")
	}
	generation = testRuntimeGeneration()
	generation.Master.OwnerUID = 1000
	if validRuntimeGeneration(generation) {
		t.Fatal("non-root master must not claim a worker owned by another uid")
	}
}
