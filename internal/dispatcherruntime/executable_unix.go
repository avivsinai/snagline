//go:build linux

package dispatcherruntime

import (
	"errors"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func sealedExecutable(snapshot []byte) (*os.File, string, error) {
	descriptor, err := unix.MemfdCreate("snagline-dispatcher", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(descriptor), "snagline-dispatcher-sealed")
	if _, err := file.Write(snapshot); err != nil || file.Chmod(0o500) != nil {
		file.Close()
		return nil, "", errors.New("could not populate sealed executable")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_WRITE); err != nil {
		file.Close()
		return nil, "", errors.New("could not seal executable")
	}
	readDescriptor, err := unix.Open("/proc/self/fd/"+strconv.Itoa(descriptor), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	file.Close()
	if err != nil {
		return nil, "", errors.New("could not reopen sealed executable read-only")
	}
	readFile := os.NewFile(uintptr(readDescriptor), "snagline-dispatcher-sealed-read-only")
	flags, err := unix.FcntlInt(readFile.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		readFile.Close()
		return nil, "", errors.New("sealed executable is not read-only")
	}
	return readFile, "/proc/self/fd/3", nil
}
