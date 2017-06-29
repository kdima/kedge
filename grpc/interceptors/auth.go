package interceptors

import (
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc"
	"context"
	"fmt"
	"github.com/mwitkow/go-grpc-middleware/util/metautils"
	"github.com/Bplotka/oidc"
)

// StreamNewCallMeta adds an empty CallMeta object to the context for use by later middlewares
func StreamServerInterceptorClientAuth(useOidcAuthFallback bool, verifier oidc.Verifier) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !useOidcAuthFallback {
			return handler(srv, ss)
		}
		if !clientCertPresent(ss.Context()) {
			md := metautils.ExtractIncoming(ss.Context())
			authToken := md.Get("proxy-auth")
			token, err := verifier.Verify(ss.Context(), authToken)
			if err != nil {
				return fmt.Errorf("failed to auth")
			}
			if token.Subject == "dima@improbable.io" {
				fmt.Printf("Hi Dima\n")
			}

		}

		return fmt.Errorf("no certs no auth")
	}
}

func clientCertPresent(ctx context.Context) bool {
	peer, ok := peer.FromContext(ctx)
	if ok {
		tlsInfo := peer.AuthInfo.(credentials.TLSInfo)
		if len(tlsInfo.State.PeerCertificates) != 0 {
			return true
		} else {
			return false
		}
	}
	return false
}

func main() {
	oidcVerifier, err := oidc.NewClient(context.Background(), "https://corpauth.service.improbable.io")
	if err != nil {

		fmt.Printf("error :%v\n", err)
	}
	cffg := oidc.VerificationConfig{
		ClientID:   "1057561464504-lt9q09il29al0ir6lppon99bpcium8kp.apps.googleusercontent.com",
	}
	verifier := oidcVerifier.Verifier(cffg)
	token, err := verifier.Verify(context.Background(), "eyJhbGciOiJSUzI1NiIsImtpZCI6IjNfRjBjZ2syWVcydkNoQXlYa0xYUUJjRDB0YTVEUFZUdFFOblRYaldiMkUtcyJ9.eyJhdF9oYXNoIjoiLW1aWjVmcGV6ZE93WkdqUC1KMmJPQSIsImF1ZCI6IjEwNTc1NjE0NjQ1MDQtbHQ5cTA5aWwyOWFsMGlyNmxwcG9uOTlicGNpdW04a3AuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhenAiOiIxMDU3NTYxNDY0NTA0LWx0OXEwOWlsMjlhbDBpcjZscHBvbjk5YnBjaXVtOGtwLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJkaW1hQGltcHJvYmFibGUuaW8iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNDk2ODYxMjU3LCJpYXQiOjE0OTY4NTc2NTcsImlzcyI6Imh0dHBzOi8vY29ycGF1dGguc2VydmljZS5pbXByb2JhYmxlLmlvIiwibG9jYWxlIjoiZW4iLCJuYW1lIjoiRGltYSBLaXNsb3YiLCJwZXJtcyI6WyJjb3JwZW5nLXByb2QiLCJpbmZyYS1hcGktcHJvZCIsImluZnJhLWFwaS1zdGFnaW5nIiwiaW5mcmEtYXBpLXRlc3RpbmciLCJpbmZyYS1jbHVzdGVyLXByb2QiLCJpbmZyYS1jbHVzdGVyLXN0YWdpbmciLCJpbmZyYS1jbHVzdGVyLXRlc3RpbmciLCJxdWFsaWZ5LXRlc3QiLCJ3ZWJ0b29scy1wcm9kIiwid2VidG9vbHMtc3RhZ2luZyIsIndlYnRvb2xzLXRlc3RpbmciLCJlbmctcHJvZCJdLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tLy04ZGtDSndXSHR3US9BQUFBQUFBQUFBSS9BQUFBQUFBQUFBby95TGZCcmNocWtSay9zOTYtYy9waG90by5qcGciLCJzdWIiOiIxMTcwNzAwODI4OTU1MTc0OTk3ODQiLCJ0ZWFtcyI6WyJpbmZyYS1hZG1pbiIsImluZnJhLWNsdXN0ZXIiXX0.IXxaPirQrvchUCfpmVFRpM5w-wdZNXdM08fGCecxA1YjJgsOkEMoKmgSthK3Al1NHfXvbpp6AojOxCAvnR5Irtkx8VmNYB9-Q_s8kSOGtRA5blrUT3AzvVrMzYRs7zRzBZ_uc5eQlOpgp3vunVEVQPOaOAJJq5ru5qt9pi__EFjZNLZNIBRQEp8RKPeY0nyKpul4HzJzeG6lqKh3rJAYaUpC2pEtXLb1AVOfDFgP1v-Plq_b0OQHawGwsdSKHZ_ZZ2jCDaC6deWdQ8mXIjTr80ZU_fOECTU18FKE6LLC2S4QIw4CvlrZk4eYJ8-4RNxCDMUTQ3QunSQEle7Aw-yT9A")
	if err != nil {
		fmt.Printf("verify failed %v\n", err)
	}
	fmt.Printf("token is %v\n", token)
}
