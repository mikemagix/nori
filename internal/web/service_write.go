package web

import (
	"context"
	"errors"

	"nori/internal/store"
)

type environmentMode uint8

const (
	dashboardEnvironment environmentMode = iota
	templateEnvironment
)

// ordinaryWrite carries a transport-neutral ordinary service candidate. The
// adapters keep their own representations, while this path owns validation
// and chooses the matching atomic store operation.
type ordinaryWrite struct {
	Service         *store.Service
	Previous        *store.Service
	Environment     *string
	EnvironmentMode environmentMode
}

type ordinaryValidationError struct{ err error }

func (e *ordinaryValidationError) Error() string { return e.err.Error() }
func (e *ordinaryValidationError) Unwrap() error { return e.err }

func (s *Server) saveOrdinaryService(ctx context.Context, write ordinaryWrite) (*store.Service, error) {
	if write.Service == nil {
		return nil, errors.New("service configuration is required")
	}
	if write.Service.IsSelf {
		return nil, errors.New("managed self-service must use its launcher workflow")
	}
	if err := validateOrdinaryService(ctx, write.Service, write.Environment, write.EnvironmentMode == templateEnvironment); err != nil {
		return nil, &ordinaryValidationError{err: err}
	}
	var err error
	if write.EnvironmentMode == templateEnvironment {
		err = s.store.SaveServiceConfigTemplate(ctx, write.Service, write.Environment, write.Previous)
	} else {
		err = s.store.SaveServiceConfig(ctx, write.Service, write.Environment, write.Previous)
	}
	if err != nil {
		return nil, err
	}
	return write.Service, nil
}
