//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package provision

import "errors"

var errUnsupportedCustody = errors.New("provision: signing key custody is not supported on this platform")

// writePrivateFile reports created=false: nothing reaches the filesystem on
// an unsupported platform, so custody stays unspent.
func writePrivateFile(string, []byte) (bool, error) { return false, errUnsupportedCustody }

func readPrivateFile(string) ([]byte, error) { return nil, errUnsupportedCustody }
