package docker

import (
	"context"
	"io"
	"strings"
)

type Fake struct {
	Containers map[string][]Container
	Err        error
	LogData    map[string]string

	ManagedContainers map[string]ManagedContainer
	Networks          map[string]ManagedResource
	Volumes           map[string]ManagedResource
	Operations        []string
	ManagedErr        error
	HealthErr         error
}

func (f *Fake) ListByService(ctx context.Context, service string) ([]Container, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Containers[service], nil
}

func (f *Fake) Logs(ctx context.Context, containerID string, tail int) (io.ReadCloser, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	data := f.LogData[containerID]
	return io.NopCloser(strings.NewReader(data)), nil
}

func (f *Fake) StartByService(ctx context.Context, service string) error {
	if f.Err != nil {
		return f.Err
	}
	cs := f.Containers[service]
	for i := range cs {
		cs[i].State = "running"
	}
	f.Containers[service] = cs
	return nil
}

func (f *Fake) StopByService(ctx context.Context, service string) error {
	if f.Err != nil {
		return f.Err
	}
	cs := f.Containers[service]
	for i := range cs {
		cs[i].State = "exited"
	}
	f.Containers[service] = cs
	return nil
}
