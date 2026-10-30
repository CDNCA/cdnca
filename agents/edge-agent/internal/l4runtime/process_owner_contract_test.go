package l4runtime

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestL4RuntimeHarnessPreservesStrictExecutableVerification(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve owner contract test path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(testFile), "../../../.."))
	production, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), "openresty.go"))
	if err != nil {
		t.Fatal(err)
	}
	productionText := string(production)
	if !strings.Contains(productionText, `os.Stat(filepath.Join(processRoot, "exe"))`) ||
		!strings.Contains(productionText, `return processIdentity{}, errors.New("OpenResty process executable is invalid")`) {
		t.Error("production process identity no longer fails closed on unreadable executable evidence")
	}
	for _, forbidden := range []string{"syscall.EACCES", "syscall.EPERM", "os.ErrPermission"} {
		if strings.Contains(productionText, forbidden) {
			t.Errorf("production process identity contains executable permission fallback %q", forbidden)
		}
	}

	harness, err := os.ReadFile(filepath.Join(repositoryRoot, "scripts", "edge-l4-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	harnessText := string(harness)
	if strings.Count(harnessText, "--cap-add SYS_PTRACE") != 1 {
		t.Error("L4 runtime harness must grant exactly one SYS_PTRACE capability")
	}
	for _, forbidden := range []string{"--privileged", "--cap-add ALL", "--cap-add=ALL"} {
		if strings.Contains(harnessText, forbidden) {
			t.Errorf("L4 runtime harness contains over-broad privilege %q", forbidden)
		}
	}
}

func TestL4SmokeWeightedPathHasBoundedOriginReadinessContract(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve owner contract test path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(testFile), "../../../.."))
	smoke, err := os.ReadFile(filepath.Join(repositoryRoot, "agents", "edge-agent", "internal", "l4runtime", "cmd", "l4-smoke", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	smokeText := string(smoke)
	for _, required := range []string{
		"ready       chan struct{}",
		"accepted    atomic.Uint64",
		"echoed      atomic.Uint64",
		"close(o.ready)",
		"TrafficHealth: &l4runtime.TrafficHealthPolicy{Request: []byte(\"health\\n\"), ExpectedResponse: []byte(\"health:ok\\n\"), TimeoutMS: 1500, Attempts: 1}",
		"if err := value.a.waitReady(); err != nil",
		"if weightedAccepted == 0 || weightedEchoed == 0",
	} {
		if !strings.Contains(smokeText, required) {
			t.Errorf("L4 smoke is missing bounded weighted readiness contract %q", required)
		}
	}
}

func TestL4SmokeWeightedHealthBudgetAllowsArm64StartupJitter(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve owner contract test path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(testFile), "../../../.."))
	smoke, err := os.ReadFile(filepath.Join(repositoryRoot, "agents", "edge-agent", "internal", "l4runtime", "cmd", "l4-smoke", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(smoke), "TrafficHealth: &l4runtime.TrafficHealthPolicy{Request: []byte(\"health\\n\"), ExpectedResponse: []byte(\"health:ok\\n\"), TimeoutMS: 1500, Attempts: 1}") {
		t.Fatal("L4 weighted smoke must allow bounded arm64 startup jitter without changing production limits")
	}
}

func TestBuildWorkerGenerationAcceptsOneDroppedWorkerOwner(t *testing.T) {
	master := processIdentity{
		PID: 41, StartTicks: 410, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: uint32(os.Geteuid()), BootID: "boot-a",
	}
	workerUID := master.OwnerUID + 1
	workers := []processIdentity{
		{PID: 51, StartTicks: 510, ExecutableDevice: 8, ExecutableInode: 80, OwnerUID: workerUID, BootID: "boot-a"},
		{PID: 52, StartTicks: 520, ExecutableDevice: 8, ExecutableInode: 80, OwnerUID: workerUID, BootID: "boot-a"},
	}

	generation, err := buildWorkerGeneration(master, workers)
	if err != nil {
		t.Fatalf("buildWorkerGeneration() error = %v", err)
	}
	if len(generation) != len(workers) {
		t.Fatalf("generation size = %d, want %d", len(generation), len(workers))
	}
	for _, worker := range workers {
		identity := workerIdentity{
			PID: worker.PID, StartTicks: worker.StartTicks,
			ExecutableDevice: worker.ExecutableDevice, ExecutableInode: worker.ExecutableInode,
			OwnerUID: worker.OwnerUID, BootID: worker.BootID,
		}
		if _, exists := generation[identity]; !exists {
			t.Fatalf("generation omitted worker identity %+v", identity)
		}
	}
}

func TestBuildWorkerGenerationRejectsForeignMasterAndMixedWorkerOwners(t *testing.T) {
	master := processIdentity{
		PID: 41, StartTicks: 410, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: uint32(os.Geteuid()), BootID: "boot-a",
	}
	worker := processIdentity{
		PID: 51, StartTicks: 510, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: master.OwnerUID + 1, BootID: "boot-a",
	}

	foreignMaster := master
	foreignMaster.OwnerUID++
	if _, err := buildWorkerGeneration(foreignMaster, []processIdentity{worker}); err == nil {
		t.Fatal("buildWorkerGeneration() accepted a foreign master owner")
	}
	mixedOwner := worker
	mixedOwner.PID++
	mixedOwner.StartTicks++
	mixedOwner.OwnerUID++
	if _, err := buildWorkerGeneration(master, []processIdentity{worker, mixedOwner}); err == nil {
		t.Fatal("buildWorkerGeneration() accepted mixed worker owners")
	}
}

func TestBuildWorkerGenerationRejectsForeignWorkerIdentity(t *testing.T) {
	master := processIdentity{
		PID: 41, StartTicks: 410, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: uint32(os.Geteuid()), BootID: "boot-a",
	}
	worker := processIdentity{
		PID: 51, StartTicks: 510, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: 65534, BootID: "boot-a",
	}
	for _, test := range []struct {
		name   string
		change func(*processIdentity)
	}{
		{name: "PID", change: func(value *processIdentity) { value.PID = master.PID }},
		{name: "start", change: func(value *processIdentity) { value.StartTicks = 0 }},
		{name: "device", change: func(value *processIdentity) { value.ExecutableDevice++ }},
		{name: "inode", change: func(value *processIdentity) { value.ExecutableInode++ }},
		{name: "boot", change: func(value *processIdentity) { value.BootID = "boot-b" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := worker
			test.change(&changed)
			if _, err := buildWorkerGeneration(master, []processIdentity{changed}); err == nil {
				t.Fatalf("buildWorkerGeneration() accepted foreign worker %+v", changed)
			}
		})
	}
}

func TestWorkerGenerationBindsKernelOwnerExecutableBootAndStart(t *testing.T) {
	master := processIdentity{
		PID: 41, StartTicks: 410, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: uint32(os.Geteuid()), BootID: "boot-a",
	}
	worker := processIdentity{
		PID: 51, StartTicks: 510, ExecutableDevice: 8, ExecutableInode: 80,
		OwnerUID: master.OwnerUID + 1, BootID: "boot-a",
	}
	generation, err := buildWorkerGeneration(master, []processIdentity{worker})
	if err != nil {
		t.Fatal(err)
	}

	changes := []struct {
		name   string
		change func(*processIdentity)
	}{
		{name: "start", change: func(value *processIdentity) { value.StartTicks++ }},
		{name: "device", change: func(value *processIdentity) { value.ExecutableDevice++ }},
		{name: "inode", change: func(value *processIdentity) { value.ExecutableInode++ }},
		{name: "owner", change: func(value *processIdentity) { value.OwnerUID++ }},
		{name: "boot", change: func(value *processIdentity) { value.BootID = "boot-b" }},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			changed := worker
			test.change(&changed)
			identity := workerIdentity{
				PID: changed.PID, StartTicks: changed.StartTicks,
				ExecutableDevice: changed.ExecutableDevice, ExecutableInode: changed.ExecutableInode,
				OwnerUID: changed.OwnerUID, BootID: changed.BootID,
			}
			if _, exists := generation[identity]; exists {
				t.Fatalf("generation accepted changed worker identity %+v", identity)
			}
		})
	}
}
