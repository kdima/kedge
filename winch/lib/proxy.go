package lib

import (
	"github.com/mwitkow/grpc-proxy/proxy"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// New builds a StreamDirector based off a backend pool and a router.
func New(conn *grpc.ClientConn) proxy.StreamDirector {
	return func(ctx context.Context, fullMethodName string) (*grpc.ClientConn, error) {
		return conn, nil
	}
}
