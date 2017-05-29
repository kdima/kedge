package interceptors

import (
	"google.golang.org/grpc"
	"golang.org/x/net/context"
	"google.golang.org/grpc/metadata"
	"fmt"
)

func UnaryServerInterceptorKedgeToken() grpc.UnaryServerInterceptor {

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		newCtx := context.WithValue(ctx, "auth_stuff", "kedge_token")
		resp, err := handler(newCtx, req)
		return resp, err
	}
}

// StreamNewCallMeta adds an empty CallMeta object to the context for use by later middlewares
func StreamServerInterceptorKedgeToken() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		md, ok := metadata.FromContext(ss.Context())
		if !ok {
			fmt.Printf("eggog!\n")
		}
		md[":authority:"] = []string{"controller.eu1-prod.internal.improbable.io"}
		moreMd := metadata.New(map[string]string{"auth_stuff": "kedge_token"})
		newMd := metadata.Join(moreMd, md)
		newCtx := metadata.NewContext(ss.Context(), newMd)
		return handler(srv, &contextServerStream{ss, newCtx})
	}
}

// contextServerStream overrides the Context retrieved by users
type contextServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (this *contextServerStream) Context() context.Context {
	return this.ctx
}
