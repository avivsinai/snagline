//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package securefile

import "errors"

var ErrRejected = errors.New("securefile: private file rejected")

func ReadPrivateExact(string, int64) ([]byte, error)   { return nil, ErrRejected }
func ReadPrivateBounded(string, int64) ([]byte, error) { return nil, ErrRejected }
func ReadRegularBounded(string, int64) ([]byte, error) { return nil, ErrRejected }
