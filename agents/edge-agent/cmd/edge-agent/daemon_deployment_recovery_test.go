package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type recoveryOrderProbe struct {
	steps *[]string
	fail  bool
}

func (p recoveryOrderProbe) Recover(context.Context) error {
	*p.steps = append(*p.steps, "deployment")
	if p.fail {
		return errors.New("recovery failed")
	}
	return nil
}

func (p recoveryOrderProbe) RecoverCertificateVersionReferences(context.Context) error {
	*p.steps = append(*p.steps, "certificate-references")
	return nil
}

func (p recoveryOrderProbe) Run(context.Context) error {
	*p.steps = append(*p.steps, "gateway")
	return nil
}

func TestDaemonRecoversDeploymentBeforeReferencesAndGateway(t *testing.T) {
	for _, fail := range []bool{false, true} {
		var steps []string
		probe := recoveryOrderProbe{steps: &steps, fail: fail}
		daemon := daemonClient{client: probe, deployment: probe, certificateDeployment: probe}
		err := daemon.Run(context.Background())
		want := []string{"deployment", "certificate-references", "gateway"}
		if fail {
			want = []string{"deployment"}
		}
		if (err != nil) != fail || !reflect.DeepEqual(steps, want) {
			t.Fatalf("fail=%v steps=%v want=%v err=%v", fail, steps, want, err)
		}
	}
}
