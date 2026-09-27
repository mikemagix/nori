package docker

import (
	"context"
	"fmt"
	"io"
	"maps"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/errdefs"
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
	for _, item := range spec.Mounts {
		host.Mounts = append(host.Mounts, mount.Mount{Type: mount.TypeVolume, Source: item.Source, Target: item.Target})
	}
	networking := &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{}}
	for _, networkName := range spec.Networks {
		networking.EndpointsConfig[networkName] = &network.EndpointSettings{}
	}
	_, err := r.cli.ContainerCreate(ctx, &container.Config{
		Image: spec.Image, Env: append([]string(nil), spec.Env...), Labels: maps.Clone(spec.Labels),
	}, host, networking, nil, spec.Name)
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

func managedError(err error) error {
	if err == nil {
		return nil
	}
	if errdefs.IsNotFound(err) {
		return fmt.Errorf("%w: %v", ErrManagedNotFound, err)
	}
	return err
}
