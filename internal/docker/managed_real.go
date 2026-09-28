package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strconv"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/errdefs"
	"github.com/docker/go-connections/nat"
)

func (r *realClient) Pull(ctx context.Context, imageRef string) error {
	stream, err := r.cli.ImagePull(ctx, imageRef, image.PullOptions{})
	if err != nil {
		return managedError(err)
	}
	defer stream.Close()
	_, err = io.Copy(io.Discard, stream)
	return managedError(err)
}

func (r *realClient) InspectContainer(ctx context.Context, name string) (ManagedContainer, error) {
	inspect, err := r.cli.ContainerInspect(ctx, name)
	if err != nil {
		return ManagedContainer{}, managedError(err)
	}
	if inspect.Config == nil {
		return ManagedContainer{}, fmt.Errorf("container %q has no configuration", name)
	}
	state := "created"
	if inspect.State != nil {
		if inspect.State.Running {
			state = "running"
		} else if inspect.State.Status != "" {
			state = inspect.State.Status
		}
	}
	result := ManagedContainer{
		ManagedContainerSpec: ManagedContainerSpec{
			Name:   name,
			Image:  inspect.Config.Image,
			Labels: maps.Clone(inspect.Config.Labels),
			Env:    append([]string(nil), inspect.Config.Env...),
		},
		State: state,
	}
	if inspect.NetworkSettings != nil {
		for networkName := range inspect.NetworkSettings.Networks {
			result.Networks = append(result.Networks, networkName)
		}
	}
	return result, nil
}

func (r *realClient) CreateContainer(ctx context.Context, spec ManagedContainerSpec) error {
	host := &container.HostConfig{
		RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyMode(spec.RestartPolicy)},
	}
	containerConfig := &container.Config{
		Image: spec.Image, Env: append([]string(nil), spec.Env...), Labels: maps.Clone(spec.Labels),
	}
	if spec.PublishedPort > 0 {
		port := nat.Port(fmt.Sprintf("%d/tcp", spec.PublishedPort))
		containerConfig.ExposedPorts = nat.PortSet{port: struct{}{}}
		host.PortBindings = nat.PortMap{port: []nat.PortBinding{{HostPort: strconv.Itoa(spec.PublishedPort)}}}
	}
	for _, item := range spec.Mounts {
		host.Mounts = append(host.Mounts, mount.Mount{Type: mount.TypeVolume, Source: item.Source, Target: item.Target})
	}
	networking := &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{}}
	for _, networkName := range spec.Networks {
		networking.EndpointsConfig[networkName] = &network.EndpointSettings{}
	}
	_, err := r.cli.ContainerCreate(ctx, containerConfig, host, networking, nil, spec.Name)
	return managedError(err)
}

func (r *realClient) StartContainer(ctx context.Context, name string) error {
	return managedError(r.cli.ContainerStart(ctx, name, container.StartOptions{}))
}

func (r *realClient) StopContainer(ctx context.Context, name string) error {
	return managedError(r.cli.ContainerStop(ctx, name, container.StopOptions{}))
}

func (r *realClient) RemoveContainer(ctx context.Context, name string) error {
	return managedError(r.cli.ContainerRemove(ctx, name, container.RemoveOptions{Force: true}))
}

func (r *realClient) RenameContainer(ctx context.Context, oldName, newName string) error {
	return managedError(r.cli.ContainerRename(ctx, oldName, newName))
}

func (r *realClient) InspectNetwork(ctx context.Context, name string) (ManagedResource, error) {
	inspect, err := r.cli.NetworkInspect(ctx, name, network.InspectOptions{})
	if err != nil {
		return ManagedResource{}, managedError(err)
	}
	return ManagedResource{Name: inspect.Name, Labels: maps.Clone(inspect.Labels)}, nil
}

func (r *realClient) InspectVolume(ctx context.Context, name string) (ManagedResource, error) {
	inspect, err := r.cli.VolumeInspect(ctx, name)
	if err != nil {
		return ManagedResource{}, managedError(err)
	}
	return ManagedResource{Name: inspect.Name, Labels: maps.Clone(inspect.Labels)}, nil
}

func (r *realClient) EnsureNetwork(ctx context.Context, want ManagedResource) error {
	inspect, err := r.cli.NetworkInspect(ctx, want.Name, network.InspectOptions{})
	if err == nil {
		return checkOwnership(ManagedResource{Name: inspect.Name, Labels: inspect.Labels}, want)
	}
	if !errdefs.IsNotFound(err) {
		return managedError(err)
	}
	_, err = r.cli.NetworkCreate(ctx, want.Name, network.CreateOptions{Driver: network.NetworkBridge, Internal: true, Labels: maps.Clone(want.Labels)})
	return managedError(err)
}

func (r *realClient) EnsureVolume(ctx context.Context, want ManagedResource) error {
	inspect, err := r.cli.VolumeInspect(ctx, want.Name)
	if err == nil {
		return checkOwnership(ManagedResource{Name: inspect.Name, Labels: inspect.Labels}, want)
	}
	if !errdefs.IsNotFound(err) {
		return managedError(err)
	}
	_, err = r.cli.VolumeCreate(ctx, volume.CreateOptions{Name: want.Name, Labels: maps.Clone(want.Labels)})
	return managedError(err)
}

func (r *realClient) RunProbe(ctx context.Context, probe ManagedProbe) error {
	if probe.Container == "" {
		return r.runNetworkProbe(ctx, probe)
	}
	execID, err := r.cli.ContainerExecCreate(ctx, probe.Container, container.ExecOptions{
		Cmd:          []string{"/bin/sh", "-ec", probe.Command},
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		return managedError(err)
	}
	if err := r.cli.ContainerExecStart(ctx, execID.ID, container.ExecStartOptions{}); err != nil {
		return managedError(err)
	}
	inspect, err := r.cli.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return managedError(err)
	}
	if inspect.ExitCode != 0 {
		return fmt.Errorf("health probe for %s exited with status %d", probe.Container, inspect.ExitCode)
	}
	return nil
}

func (r *realClient) runNetworkProbe(ctx context.Context, probe ManagedProbe) error {
	if probe.Image == "" || probe.Network == "" {
		return fmt.Errorf("network health probe requires image and network")
	}
	networking := &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{
		probe.Network: &network.EndpointSettings{},
	}}
	created, err := r.cli.ContainerCreate(ctx, &container.Config{
		Image: probe.Image, Env: append([]string(nil), probe.Env...), Cmd: []string{"/bin/sh", "-ec", probe.Command},
	}, &container.HostConfig{}, networking, nil, "")
	if err != nil {
		return managedError(err)
	}
	defer r.cli.ContainerRemove(context.Background(), created.ID, container.RemoveOptions{Force: true})
	if err := r.cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		return managedError(err)
	}
	status, errCh := r.cli.ContainerWait(ctx, created.ID, container.WaitConditionNotRunning)
	select {
	case result := <-status:
		if result.StatusCode != 0 {
			return fmt.Errorf("network health probe exited with status %d", result.StatusCode)
		}
	case err := <-errCh:
		if err != nil {
			return managedError(err)
		}
		return errors.New("network health probe did not report an exit status")
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func managedError(err error) error {
	if err == nil {
		return nil
	}
	if errdefs.IsNotFound(err) {
		return fmt.Errorf("%w: %v", ErrManagedNotFound, err)
	}
	return err
}
