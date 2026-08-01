//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package runtimeops

import (
	"context"
	"errors"
	"net"
)

type Server struct{}

func Start(context.Context, string, HandlerConfig) (*Server, error) {
	return nil, errors.New("runtimeops: private Unix sockets are unsupported on this platform")
}
func (s *Server) Path() string { return "" }
func (s *Server) Close() error { return nil }
func ListenUnix(string) (net.Listener, error) {
	return nil, errors.New("runtimeops: private Unix sockets are unsupported on this platform")
}
