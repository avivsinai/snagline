//go:build !linux && !darwin

package dispatcherruntime

import "os"

func fileOwnerUID(os.FileInfo) (uint32, bool) {
	return 0, false
}
