package docker

import (
	"context"
	"errors"
	"fmt"
	"maps"
)

var (
	ErrManagedNotFound   = errors.New("managed Docker resource not found")
	ErrOwnershipConflict = errors.New("Docker resource ownership conflict")
	ErrManagedExists     = errors.New("managed Docker resource already exists")
)

// ManagedResource is the safe ownership surface for a network or volume.
// Template lifecycle code validates labels before it reuses a resource.
type ManagedResource struct {
	Name   string
	Labels map[string]string
}

type ManagedMount struct {
	Source string
	Target string
}

// ManagedContainerSpec is a narrow replacement for Docker SDK configuration.
// Environment entries are accepted only by the native executor and must not be
// copied into previews, deployments, or errors.
type ManagedContainerSpec struct {
	Name          string
	Image         string
	Labels        map[string]string
	Env           []string
	Networks      []string
	Mounts        []ManagedMount
	RestartPolicy string
}

type ManagedContainer struct {
	ManagedContainerSpec
	State string
}

// ManagedProbe runs a bounded, non-interactive command inside a managed
// container. It keeps the executor on a narrow, typed Docker surface rather
// than exposing arbitrary Docker commands through the dashboard or MCP.
type ManagedProbe struct {
	Container string
	Command   string
	// Image and Network create a short-lived probe container. They are used
	// for cross-network database readiness rather than executing inside the
	// database container itself.
	Image   string
	Network string
	Env     []string
}

// ManagedClient adds only the operations required by Nori's managed templates.
// It intentionally does not expose a general Docker command primitive.
type ManagedClient interface {
	Pull(context.Context, string) error
	InspectContainer(context.Context, string) (ManagedContainer, error)
	CreateContainer(context.Context, ManagedContainerSpec) error
	StartContainer(context.Context, string) error
	StopContainer(context.Context, string) error
	RemoveContainer(context.Context, string) error
	RenameContainer(context.Context, string, string) error
	InspectNetwork(context.Context, string) (ManagedResource, error)
	InspectVolume(context.Context, string) (ManagedResource, error)
	EnsureNetwork(context.Context, ManagedResource) error
	EnsureVolume(context.Context, ManagedResource) error
	RunProbe(context.Context, ManagedProbe) error
}

func (f *Fake) managedFailure() error {
	if f.ManagedErr != nil {
		return f.ManagedErr
	}
	return nil
}

func (f *Fake) Pull(_ context.Context, image string) error {
	if err := f.managedFailure(); err != nil {
		return err
	}
	f.Operations = append(f.Operations, "pull "+image)
	return nil
}

func (f *Fake) InspectContainer(_ context.Context, name string) (ManagedContainer, error) {
	if err := f.managedFailure(); err != nil {
		return ManagedContainer{}, err
	}
	f.Operations = append(f.Operations, "inspect container "+name)
	container, ok := f.ManagedContainers[name]
	if !ok {
		return ManagedContainer{}, fmt.Errorf("%w: container %s", ErrManagedNotFound, name)
	}
	return cloneContainer(container), nil
}

func (f *Fake) CreateContainer(_ context.Context, spec ManagedContainerSpec) error {
	if err := f.managedFailure(); err != nil {
		return err
	}
	if f.ManagedContainers == nil {
		f.ManagedContainers = map[string]ManagedContainer{}
	}
	if _, exists := f.ManagedContainers[spec.Name]; exists {
		return fmt.Errorf("%w: container %s", ErrManagedExists, spec.Name)
	}
	f.Operations = append(f.Operations, "create container "+spec.Name)
	f.ManagedContainers[spec.Name] = ManagedContainer{ManagedContainerSpec: cloneSpec(spec), State: "created"}
	return nil
}

func (f *Fake) StartContainer(_ context.Context, name string) error {
	if err := f.managedFailure(); err != nil {
		return err
	}
	container, ok := f.ManagedContainers[name]
	if !ok {
		return fmt.Errorf("%w: container %s", ErrManagedNotFound, name)
	}
	f.Operations = append(f.Operations, "start container "+name)
	container.State = "running"
	f.ManagedContainers[name] = container
	return nil
}

func (f *Fake) StopContainer(_ context.Context, name string) error {
	if err := f.managedFailure(); err != nil {
		return err
	}
	container, ok := f.ManagedContainers[name]
	if !ok {
		return fmt.Errorf("%w: container %s", ErrManagedNotFound, name)
	}
	f.Operations = append(f.Operations, "stop container "+name)
	container.State = "exited"
	f.ManagedContainers[name] = container
	return nil
}

func (f *Fake) RemoveContainer(_ context.Context, name string) error {
	if err := f.managedFailure(); err != nil {
		return err
	}
	if _, ok := f.ManagedContainers[name]; !ok {
		return fmt.Errorf("%w: container %s", ErrManagedNotFound, name)
	}
	f.Operations = append(f.Operations, "remove container "+name)
	delete(f.ManagedContainers, name)
	return nil
}

func (f *Fake) RenameContainer(_ context.Context, oldName, newName string) error {
	if err := f.managedFailure(); err != nil {
		return err
	}
	container, ok := f.ManagedContainers[oldName]
	if !ok {
		return fmt.Errorf("%w: container %s", ErrManagedNotFound, oldName)
	}
	if _, exists := f.ManagedContainers[newName]; exists {
		return fmt.Errorf("%w: container %s", ErrManagedExists, newName)
	}
	f.Operations = append(f.Operations, "rename container "+oldName+" "+newName)
	delete(f.ManagedContainers, oldName)
	container.Name = newName
	f.ManagedContainers[newName] = container
	return nil
}

func (f *Fake) InspectNetwork(_ context.Context, name string) (ManagedResource, error) {
	if err := f.managedFailure(); err != nil {
		return ManagedResource{}, err
	}
	f.Operations = append(f.Operations, "inspect network "+name)
	resource, ok := f.Networks[name]
	if !ok {
		return ManagedResource{}, fmt.Errorf("%w: network %s", ErrManagedNotFound, name)
	}
	return cloneResource(resource), nil
}

func (f *Fake) InspectVolume(_ context.Context, name string) (ManagedResource, error) {
	if err := f.managedFailure(); err != nil {
		return ManagedResource{}, err
	}
	f.Operations = append(f.Operations, "inspect volume "+name)
	resource, ok := f.Volumes[name]
	if !ok {
		return ManagedResource{}, fmt.Errorf("%w: volume %s", ErrManagedNotFound, name)
	}
	return cloneResource(resource), nil
}

func (f *Fake) EnsureNetwork(_ context.Context, want ManagedResource) error {
	if err := f.managedFailure(); err != nil {
		return err
	}
	f.Operations = append(f.Operations, "inspect network "+want.Name)
	if got, ok := f.Networks[want.Name]; ok {
		return checkOwnership(got, want)
	}
	if f.Networks == nil {
		f.Networks = map[string]ManagedResource{}
	}
	f.Operations = append(f.Operations, "create network "+want.Name)
	f.Networks[want.Name] = cloneResource(want)
	return nil
}

func (f *Fake) EnsureVolume(_ context.Context, want ManagedResource) error {
	if err := f.managedFailure(); err != nil {
		return err
	}
	f.Operations = append(f.Operations, "inspect volume "+want.Name)
	if got, ok := f.Volumes[want.Name]; ok {
		return checkOwnership(got, want)
	}
	if f.Volumes == nil {
		f.Volumes = map[string]ManagedResource{}
	}
	f.Operations = append(f.Operations, "create volume "+want.Name)
	f.Volumes[want.Name] = cloneResource(want)
	return nil
}

func (f *Fake) RunProbe(_ context.Context, probe ManagedProbe) error {
	if err := f.managedFailure(); err != nil {
		return err
	}
	if probe.Network != "" {
		f.Operations = append(f.Operations, "probe network "+probe.Network)
	} else {
		f.Operations = append(f.Operations, "probe container "+probe.Container)
	}
	return f.HealthErr
}

func checkOwnership(got, want ManagedResource) error {
	for key, expected := range want.Labels {
		if got.Labels[key] != expected {
			return fmt.Errorf("%w: %s %q has %s=%q, expected %q", ErrOwnershipConflict, want.Name, want.Name, key, got.Labels[key], expected)
		}
	}
	return nil
}

func cloneResource(resource ManagedResource) ManagedResource {
	return ManagedResource{Name: resource.Name, Labels: maps.Clone(resource.Labels)}
}

func cloneContainer(container ManagedContainer) ManagedContainer {
	container.ManagedContainerSpec = cloneSpec(container.ManagedContainerSpec)
	return container
}

func cloneSpec(spec ManagedContainerSpec) ManagedContainerSpec {
	spec.Labels = maps.Clone(spec.Labels)
	spec.Env = append([]string(nil), spec.Env...)
	spec.Networks = append([]string(nil), spec.Networks...)
	spec.Mounts = append([]ManagedMount(nil), spec.Mounts...)
	return spec
}
