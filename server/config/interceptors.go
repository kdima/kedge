package config

import (
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/credentials"
)

// StreamNewCallMeta adds an empty CallMeta object to the context for use by later middlewares
func StreamServerInterceptorClientAuth() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		peer, ok := peer.FromContext(ss.Context())
		if ok {
			tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
			if len(tlsInfo.State.PeerCertificates) != 0 {
				fmt.Printf("presented client cert\n")
			} else {
				fmt.Printf("did not present client cert\n")
			}
		} else {
			fmt.Printf("no peer info\n")
		}
		return handler(srv, ss)
	}
}
