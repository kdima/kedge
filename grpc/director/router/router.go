package router

import (
	pb "github.com/mwitkow/kedge/_protogen/kedge/config/grpc/routes"

	"strings"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"fmt"
	"net"
)

var (
	emptyMd       = metadata.Pairs()
	routeNotFound = grpc.Errorf(codes.Unimplemented, "unknown route to service")
)

type Router interface {
	// Route returns a backend name for a given call, or an error.
	Route(ctx context.Context, fullMethodName string) (backendName string, err error)
}

type router struct {
	routes []*pb.Route
}

func NewStatic(routes []*pb.Route) *router {
	return &router{routes: routes}
}

func (r *router) Route(ctx context.Context, fullMethodName string) (backendName string, err error) {
	md, ok := metadata.FromContext(ctx)
	if !ok {
		md = emptyMd
	}
	fmt.Printf("Metadata is %+v\n", md)
	fmt.Printf("ctx is %+v\n", ctx)
	fmt.Printf("method name is %s\n", fullMethodName)
	if strings.HasPrefix(fullMethodName, "/") {
		fullMethodName = fullMethodName[1:]
	}
	fmt.Printf("routes are %v\n", r.routes)
	for _, route := range r.routes {
		if !r.serviceNameMatches(fullMethodName, route.ServiceNameMatcher) {
			fmt.Printf("srv matcher\n")
			continue
		}
		if !r.authorityMatches(md, route.AuthorityMatcher) {
			fmt.Printf("auth matcher\n")
			continue
		}
		if !r.metadataMatches(md, route.MetadataMatcher) {
			fmt.Printf("md matcher\n")
			continue
		}
		return route.BackendName, nil
	}
	return "", routeNotFound
}

func (r *router) serviceNameMatches(fullMethodName string, matcher string) bool {
	if matcher == "" || matcher == "*" {
		return true
	}
	if matcher[len(matcher)-1] == '*' {
		return strings.HasPrefix(fullMethodName, matcher[0:len(matcher)-1])
	}
	return fullMethodName == matcher
}

func (r *router) authorityMatches(md metadata.MD, matcher string) bool {
	if matcher == "" {
		return true
	}
	auth, ok := md[":authority"]
	if !ok || len(auth) == 0 {
		return false // there was no authority header and it was expected
	}
	host, _, err := net.SplitHostPort(auth[0])
	if err != nil {
		fmt.Printf("could not split host and port\n")
		return false
	}
	return host == matcher
}

func (r *router) metadataMatches(md metadata.MD, expectedKv map[string]string) bool {
	for expK, expV := range expectedKv {
		vals, ok := md[strings.ToLower(expK)]
		if !ok {
			return false // key doesn't exist
		}
		found := false
		for _, v := range vals {
			if v == expV {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
