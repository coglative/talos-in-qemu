//go:build !linux

package qemu

import (
	"errors"
	"syscall"
)

var errGuestEgressLinuxOnly = errors.New("TINQ_GUEST_UID is Linux only")

func (g *guestEgress) install() error                           { return errGuestEgressLinuxOnly }
func (g *guestEgress) credential() (*syscall.Credential, error) { return nil, errGuestEgressLinuxOnly }
func (g *guestEgress) own(string) error                         { return errGuestEgressLinuxOnly }
