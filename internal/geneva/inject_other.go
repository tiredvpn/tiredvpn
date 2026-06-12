//go:build !linux

package geneva

import (
	"context"
	"fmt"
)

// Injector is a no-op on non-Linux platforms.
type Injector struct{}

// NewInjector returns a stub Injector that always fails to start.
func NewInjector(_ uint16, _ []*Strategy) *Injector {
	return &Injector{}
}

// Start always returns an error on non-Linux.
func (inj *Injector) Start(_ context.Context) error {
	return fmt.Errorf("geneva NFQUEUE injection requires Linux")
}

// Stop is a no-op.
func (inj *Injector) Stop() {}
