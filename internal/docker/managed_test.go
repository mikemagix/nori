package docker

import (
	"context"
	"errors"
	"testing"

	"github.com/docker/docker/api/types/container"
)

func TestWaitForExecCompletionWaitsForRunningExec(t *testing.T) {
	calls := 0
	err := waitForExecCompletion(context.Background(), func(context.Context) (container.ExecInspect, error) {
		calls++
		return container.ExecInspect{Running: calls == 1}, nil
	}, "nori-1-app")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("inspect calls = %d, want 2", calls)
	}
}

func TestFakeEnsureManagedResourceRejectsForeignOwnership(t *testing.T) {
	fake := &Fake{
		Networks: map[string]ManagedResource{
			"nori-1-db": {Name: "nori-1-db", Labels: map[string]string{"nori.service": "other"}},
		},
	}
	want := map[string]string{
		"nori.service": "api", "nori.template": "1", "nori.service-id": "1", "nori.role": "internal-network",
	}
	if err := fake.EnsureNetwork(context.Background(), ManagedResource{Name: "nori-1-db", Labels: want}); !errors.Is(err, ErrOwnershipConflict) {
		t.Fatalf("EnsureNetwork error = %v, want ErrOwnershipConflict", err)
	}
	if len(fake.Operations) != 1 || fake.Operations[0] != "inspect network nori-1-db" {
		t.Fatalf("operations = %v", fake.Operations)
	}
}

func TestFakeManagedContainerLifecycleRecordsSafeOrder(t *testing.T) {
	fake := &Fake{}
	ctx := context.Background()
	spec := ManagedContainerSpec{
		Name: "nori-2-app-candidate", Image: "example/api@sha256:abc",
		Labels:   map[string]string{"nori.service": "api", "nori.template": "1", "nori.service-id": "2", "nori.role": "candidate"},
		Networks: []string{"proxy"}, Env: []string{"PORT=8080"},
	}
	if err := fake.Pull(ctx, spec.Image); err != nil {
		t.Fatal(err)
	}
	if err := fake.CreateContainer(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := fake.StartContainer(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	got, err := fake.InspectContainer(ctx, spec.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "running" || got.Image != spec.Image || got.Labels["nori.role"] != "candidate" {
		t.Fatalf("container = %+v", got)
	}
	want := []string{"pull example/api@sha256:abc", "create container nori-2-app-candidate", "start container nori-2-app-candidate"}
	for i, operation := range want {
		if fake.Operations[i] != operation {
			t.Fatalf("operation %d = %q, want %q", i, fake.Operations[i], operation)
		}
	}
}
