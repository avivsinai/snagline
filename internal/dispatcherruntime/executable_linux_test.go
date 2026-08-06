//go:build linux

package dispatcherruntime

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSealedExecutableInheritedDescriptorIsReadOnly(t *testing.T) {
	executable, _, err := sealedExecutable([]byte("#!/bin/sh\nexit 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	flags, err := unix.FcntlInt(executable.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatalf("inherited descriptor access mode=%#x, want O_RDONLY", flags&unix.O_ACCMODE)
	}
	if _, err := executable.Write([]byte("attacker")); err == nil {
		t.Fatal("write through inherited executable descriptor succeeded")
	}
}
