package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	status "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

// empty struct because this isn't a fancy example
type AuthorizationServer struct{}

// inject a header that can be used for future rate limiting
func (a *AuthorizationServer) Check(ctx context.Context, req *auth.CheckRequest) (*auth.CheckResponse, error) {
	fmt.Printf("HELLOWORLD")
	log.Printf("HELLO WORLD")
	authHeader, ok := req.Attributes.Request.Http.Headers["authorization"]
	var splitToken []string
	if ok {
		splitToken = strings.Split(authHeader, "Bearer ")
	}
	if len(splitToken) == 2 {
		token := splitToken[1]
		sha := sha256.New()
		sha.Write([]byte(token))
		tokenSha := base64.StdEncoding.EncodeToString(sha.Sum(nil))

		// valid tokens have exactly 3 characters. #secure.
		// Normally this is where you'd go check with the system that knows if it's a valid token.

		if len(token) == 3 {

			log.Printf("HELLO WORLD")
			return &auth.CheckResponse{
				Status: &status.Status{Code: 5},
				HttpResponse: &auth.CheckResponse_OkResponse{
					OkResponse: &auth.OkHttpResponse{
						Headers: []*core.HeaderValueOption{
							{
								Header: &core.HeaderValue{
									Key:   "x-ext-auth-ratelimit",
									Value: tokenSha,
								},
							},
						},
					},
				},
			}, nil
		}
	}
	return &auth.CheckResponse{
		Status: &status.Status{Code: 500},
		HttpResponse: &auth.CheckResponse_DeniedResponse{
			DeniedResponse: &auth.DeniedHttpResponse{
				Status: &v3.HttpStatus{
					Code: v3.StatusCode_Unauthorized,
				},
				Body: "Need an Authorization Header with a 3 character bearer token! #secure",
			},
		},
	}, nil
}

func main() {
	// create a TCP listener on port 4000
	lis, err := net.Listen("tcp", ":4000")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("listening on %s", lis.Addr())

	grpcServer := grpc.NewServer()
	authServer := &AuthorizationServer{}
	auth.RegisterAuthorizationServer(grpcServer, authServer)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}
