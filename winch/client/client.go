package main

import (
	"net"
	"time"

	"golang.org/x/net/context"
	"github.com/Sirupsen/logrus"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	pb_base "github.com/mwitkow/kedge/_protogen/base"

	"io"
	"os"

	"google.golang.org/grpc"
	"fmt"
)

var (
	proxyHostPort = "127.0.0.1:9081" // use 8081 for plain text
)

func main() {
	//tlsConfig := &tls.Config{
	//	InsecureSkipVerify: true, // we use a self signed cert
	//}
	logrus.SetOutput(os.Stdout)
	conn, err := grpc.Dial("controller.eu1-prod.improbable.local:9999",
		//grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithInsecure(),
		grpc.WithDialer(spoofedGrpcDialer),
	)
	if err != nil {
		logrus.Fatalf("cannot dial: %v", err)
	}
	ctx, _ := context.WithTimeout(context.TODO(), 5*time.Second)
	client := pb_base.NewServerStatusClient(conn)
	listClient, err := client.FlagzList(ctx, &google_protobuf.Empty{})
	if err != nil {
		logrus.Fatalf("request failed: %v", err)
	}
	for {
		msg, err := listClient.Recv()
		if err == io.EOF {
			fmt.Printf("client get eof")
			break
		} else if err != nil {
			logrus.Fatalf("request failed mid way: %v", err)
		}
		logrus.Info("Flag: ", msg)
	}
}

// spoofedGrpcDialer pretends to dial over a remote DNS name, but resolves to localhost.
// This is to send the requests to the director
func spoofedGrpcDialer(addr string, t time.Duration) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	switch host {
	case "controller.eu1-prod.improbable.local":
		return net.DialTimeout("tcp", proxyHostPort, t)
	default:
		return net.DialTimeout("tcp", addr, t)
	}
}
