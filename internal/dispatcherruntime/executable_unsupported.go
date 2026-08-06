//go:build !linux

package dispatcherruntime

import (
	"errors"
	"os"
)

func sealedExecutable([]byte) (*os.File, string, error) {
	return nil, "", errors.New("dispatcher executable pinning requires Linux /proc/self/fd")
}
