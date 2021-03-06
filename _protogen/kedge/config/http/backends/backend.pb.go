// Code generated by protoc-gen-go.
// source: kedge/config/http/backends/backend.proto
// DO NOT EDIT!

/*
Package kedge_config_http_backends is a generated protocol buffer package.

It is generated from these files:
	kedge/config/http/backends/backend.proto

It has these top-level messages:
	Backend
	Middleware
	Security
*/
package kedge_config_http_backends

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/mwitkow/go-proto-validators"
import  kedge_config_common_resolvers "github.com/mwitkow/kedge/_protogen/kedge/config/common/resolvers"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// / Balancer chooses which HTTP backend balancing policy to use.
type Balancer int32

const (
	// ROUND_ROBIN is the simpliest and default load balancing policy
	Balancer_ROUND_ROBIN Balancer = 0
)

var Balancer_name = map[int32]string{
	0: "ROUND_ROBIN",
}
var Balancer_value = map[string]int32{
	"ROUND_ROBIN": 0,
}

func (x Balancer) String() string {
	return proto.EnumName(Balancer_name, int32(x))
}
func (Balancer) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// / Backend is a pool of HTTP endpoints that are kept open
type Backend struct {
	// / name is the string identifying the bakcend in all other conifgs.
	Name string `protobuf:"bytes,1,opt,name=name" json:"name,omitempty"`
	// / balancer decides which balancing policy to use.
	Balancer Balancer `protobuf:"varint,2,opt,name=balancer,enum=kedge.config.http.backends.Balancer" json:"balancer,omitempty"`
	// / disable_conntracking turns off the /debug/events tracing and Prometheus monitoring of the pool sie for this backend.
	DisableConntracking bool `protobuf:"varint,3,opt,name=disable_conntracking,json=disableConntracking" json:"disable_conntracking,omitempty"`
	// / security controls the TLS connection details for the backend (HTTPS). If not present, insecure HTTTP mode is used.
	Security *Security `protobuf:"bytes,4,opt,name=security" json:"security,omitempty"`
	// / interceptors controls what middleware will be available on every call made to this backend.
	// / These will be executed in order from left to right.
	Middlewares []*Middleware `protobuf:"bytes,5,rep,name=middlewares" json:"middlewares,omitempty"`
	// Types that are valid to be assigned to Resolver:
	//	*Backend_Srv
	//	*Backend_K8S
	Resolver isBackend_Resolver `protobuf_oneof:"resolver"`
}

func (m *Backend) Reset()                    { *m = Backend{} }
func (m *Backend) String() string            { return proto.CompactTextString(m) }
func (*Backend) ProtoMessage()               {}
func (*Backend) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type isBackend_Resolver interface {
	isBackend_Resolver()
}

type Backend_Srv struct {
	Srv *kedge_config_common_resolvers.SrvResolver `protobuf:"bytes,10,opt,name=srv,oneof"`
}
type Backend_K8S struct {
	K8S *kedge_config_common_resolvers.KubeResolver `protobuf:"bytes,11,opt,name=k8s,oneof"`
}

func (*Backend_Srv) isBackend_Resolver() {}
func (*Backend_K8S) isBackend_Resolver() {}

func (m *Backend) GetResolver() isBackend_Resolver {
	if m != nil {
		return m.Resolver
	}
	return nil
}

func (m *Backend) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Backend) GetBalancer() Balancer {
	if m != nil {
		return m.Balancer
	}
	return Balancer_ROUND_ROBIN
}

func (m *Backend) GetDisableConntracking() bool {
	if m != nil {
		return m.DisableConntracking
	}
	return false
}

func (m *Backend) GetSecurity() *Security {
	if m != nil {
		return m.Security
	}
	return nil
}

func (m *Backend) GetMiddlewares() []*Middleware {
	if m != nil {
		return m.Middlewares
	}
	return nil
}

func (m *Backend) GetSrv() *kedge_config_common_resolvers.SrvResolver {
	if x, ok := m.GetResolver().(*Backend_Srv); ok {
		return x.Srv
	}
	return nil
}

func (m *Backend) GetK8S() *kedge_config_common_resolvers.KubeResolver {
	if x, ok := m.GetResolver().(*Backend_K8S); ok {
		return x.K8S
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Backend) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Backend_OneofMarshaler, _Backend_OneofUnmarshaler, _Backend_OneofSizer, []interface{}{
		(*Backend_Srv)(nil),
		(*Backend_K8S)(nil),
	}
}

func _Backend_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Backend)
	// resolver
	switch x := m.Resolver.(type) {
	case *Backend_Srv:
		b.EncodeVarint(10<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Srv); err != nil {
			return err
		}
	case *Backend_K8S:
		b.EncodeVarint(11<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.K8S); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Backend.Resolver has unexpected type %T", x)
	}
	return nil
}

func _Backend_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Backend)
	switch tag {
	case 10: // resolver.srv
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(kedge_config_common_resolvers.SrvResolver)
		err := b.DecodeMessage(msg)
		m.Resolver = &Backend_Srv{msg}
		return true, err
	case 11: // resolver.k8s
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(kedge_config_common_resolvers.KubeResolver)
		err := b.DecodeMessage(msg)
		m.Resolver = &Backend_K8S{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Backend_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Backend)
	// resolver
	switch x := m.Resolver.(type) {
	case *Backend_Srv:
		s := proto.Size(x.Srv)
		n += proto.SizeVarint(10<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *Backend_K8S:
		s := proto.Size(x.K8S)
		n += proto.SizeVarint(11<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type Middleware struct {
	// Types that are valid to be assigned to Middleware:
	//	*Middleware_Prometheus
	Middleware isMiddleware_Middleware `protobuf_oneof:"Middleware"`
}

func (m *Middleware) Reset()                    { *m = Middleware{} }
func (m *Middleware) String() string            { return proto.CompactTextString(m) }
func (*Middleware) ProtoMessage()               {}
func (*Middleware) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type isMiddleware_Middleware interface {
	isMiddleware_Middleware()
}

type Middleware_Prometheus struct {
	Prometheus *Middleware_Retry `protobuf:"bytes,1,opt,name=prometheus,oneof"`
}

func (*Middleware_Prometheus) isMiddleware_Middleware() {}

func (m *Middleware) GetMiddleware() isMiddleware_Middleware {
	if m != nil {
		return m.Middleware
	}
	return nil
}

func (m *Middleware) GetPrometheus() *Middleware_Retry {
	if x, ok := m.GetMiddleware().(*Middleware_Prometheus); ok {
		return x.Prometheus
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Middleware) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Middleware_OneofMarshaler, _Middleware_OneofUnmarshaler, _Middleware_OneofSizer, []interface{}{
		(*Middleware_Prometheus)(nil),
	}
}

func _Middleware_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Middleware)
	// Middleware
	switch x := m.Middleware.(type) {
	case *Middleware_Prometheus:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.Prometheus); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("Middleware.Middleware has unexpected type %T", x)
	}
	return nil
}

func _Middleware_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Middleware)
	switch tag {
	case 1: // Middleware.prometheus
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(Middleware_Retry)
		err := b.DecodeMessage(msg)
		m.Middleware = &Middleware_Prometheus{msg}
		return true, err
	default:
		return false, nil
	}
}

func _Middleware_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Middleware)
	// Middleware
	switch x := m.Middleware.(type) {
	case *Middleware_Prometheus:
		s := proto.Size(x.Prometheus)
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type Middleware_Retry struct {
	// / retry_count specifies how many times to retry.
	RetryCount uint32 `protobuf:"varint,1,opt,name=retry_count,json=retryCount" json:"retry_count,omitempty"`
	// / on_codes specifies the list of codes to retry on.
	OnCodes []uint32 `protobuf:"varint,2,rep,packed,name=on_codes,json=onCodes" json:"on_codes,omitempty"`
}

func (m *Middleware_Retry) Reset()                    { *m = Middleware_Retry{} }
func (m *Middleware_Retry) String() string            { return proto.CompactTextString(m) }
func (*Middleware_Retry) ProtoMessage()               {}
func (*Middleware_Retry) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1, 0} }

func (m *Middleware_Retry) GetRetryCount() uint32 {
	if m != nil {
		return m.RetryCount
	}
	return 0
}

func (m *Middleware_Retry) GetOnCodes() []uint32 {
	if m != nil {
		return m.OnCodes
	}
	return nil
}

// / Security settings for a backend.
type Security struct {
	// / insecure_skip_verify skips the server certificate verification completely.
	// / No TLS config (for testclient or server) will be used. This should *not* be used in production software.
	InsecureSkipVerify bool `protobuf:"varint,1,opt,name=insecure_skip_verify,json=insecureSkipVerify" json:"insecure_skip_verify,omitempty"`
	// / config_name indicates the TlsServerConfig to be used for this connection.
	ConfigName string `protobuf:"bytes,2,opt,name=config_name,json=configName" json:"config_name,omitempty"`
}

func (m *Security) Reset()                    { *m = Security{} }
func (m *Security) String() string            { return proto.CompactTextString(m) }
func (*Security) ProtoMessage()               {}
func (*Security) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *Security) GetInsecureSkipVerify() bool {
	if m != nil {
		return m.InsecureSkipVerify
	}
	return false
}

func (m *Security) GetConfigName() string {
	if m != nil {
		return m.ConfigName
	}
	return ""
}

func init() {
	proto.RegisterType((*Backend)(nil), "kedge.config.http.backends.Backend")
	proto.RegisterType((*Middleware)(nil), "kedge.config.http.backends.Middleware")
	proto.RegisterType((*Middleware_Retry)(nil), "kedge.config.http.backends.Middleware.Retry")
	proto.RegisterType((*Security)(nil), "kedge.config.http.backends.Security")
	proto.RegisterEnum("kedge.config.http.backends.Balancer", Balancer_name, Balancer_value)
}

func init() { proto.RegisterFile("kedge/config/http/backends/backend.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 522 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x93, 0xdf, 0x6e, 0xd3, 0x30,
	0x14, 0xc6, 0x97, 0x65, 0x63, 0xe1, 0x84, 0x31, 0x30, 0x43, 0x0a, 0xe5, 0x62, 0x51, 0x35, 0xa1,
	0x30, 0xd6, 0x04, 0x0a, 0xaa, 0x76, 0x05, 0x28, 0xe5, 0xa2, 0x08, 0xd1, 0x49, 0xae, 0xe0, 0x06,
	0x41, 0x94, 0x3f, 0x5e, 0x6b, 0xa5, 0xb1, 0x2b, 0xdb, 0x6d, 0x55, 0x10, 0xcf, 0xc4, 0x3b, 0xf0,
	0x22, 0x48, 0x3c, 0x09, 0x8a, 0xd3, 0xb4, 0xdd, 0x05, 0x85, 0xbb, 0x13, 0x9f, 0xdf, 0xf7, 0x1d,
	0x1f, 0x9f, 0x13, 0xf0, 0x72, 0x92, 0x0d, 0x49, 0x90, 0x72, 0x76, 0x45, 0x87, 0xc1, 0x48, 0xa9,
	0x49, 0x90, 0xc4, 0x69, 0x4e, 0x58, 0x26, 0xeb, 0xc0, 0x9f, 0x08, 0xae, 0x38, 0x6a, 0x68, 0xd2,
	0xaf, 0x48, 0xbf, 0x24, 0xfd, 0x9a, 0x6c, 0x74, 0x86, 0x54, 0x8d, 0xa6, 0x89, 0x9f, 0xf2, 0x22,
	0x28, 0xe6, 0x54, 0xe5, 0x7c, 0x1e, 0x0c, 0x79, 0x4b, 0x0b, 0x5b, 0xb3, 0x78, 0x4c, 0xb3, 0x58,
	0x71, 0x21, 0x83, 0x55, 0x58, 0x79, 0x36, 0x5a, 0xd7, 0xaa, 0xa7, 0xbc, 0x28, 0x38, 0x0b, 0x04,
	0x91, 0x7c, 0x3c, 0x23, 0x42, 0xae, 0xa3, 0x0a, 0x6f, 0xfe, 0x34, 0xe1, 0x20, 0xac, 0x6a, 0xa2,
	0xc7, 0xb0, 0xc7, 0xe2, 0x82, 0x38, 0x86, 0x6b, 0x78, 0x37, 0xc3, 0xfb, 0xbf, 0x7f, 0x9d, 0xdc,
	0x85, 0xa3, 0x2f, 0x9f, 0xe2, 0xd6, 0xd7, 0xc8, 0xff, 0xfc, 0xad, 0x7d, 0xde, 0x79, 0xf1, 0xfd,
	0x14, 0x6b, 0x04, 0xbd, 0x06, 0x2b, 0x89, 0xc7, 0x31, 0x4b, 0x89, 0x70, 0x76, 0x5d, 0xc3, 0xbb,
	0xdd, 0x3e, 0xf5, 0xff, 0xde, 0x8c, 0x1f, 0x2e, 0x59, 0xbc, 0x52, 0xa1, 0x67, 0x70, 0x9c, 0x51,
	0x19, 0x27, 0x63, 0x12, 0xa5, 0x9c, 0x31, 0x25, 0xe2, 0x34, 0xa7, 0x6c, 0xe8, 0x98, 0xae, 0xe1,
	0x59, 0xf8, 0xde, 0x32, 0xd7, 0xdd, 0x48, 0x95, 0x45, 0x25, 0x49, 0xa7, 0x82, 0xaa, 0x85, 0xb3,
	0xe7, 0x1a, 0x9e, 0xbd, 0xbd, 0xe8, 0x60, 0xc9, 0xe2, 0x95, 0x0a, 0xf5, 0xc0, 0x2e, 0x68, 0x96,
	0x8d, 0xc9, 0x3c, 0x16, 0x44, 0x3a, 0xfb, 0xae, 0xe9, 0xd9, 0xed, 0x47, 0xdb, 0x4c, 0xde, 0xaf,
	0x70, 0xbc, 0x29, 0x45, 0x2f, 0xc1, 0x94, 0x62, 0xe6, 0x80, 0xbe, 0xc6, 0xd9, 0x75, 0x87, 0xea,
	0xd1, 0xfd, 0xf5, 0x53, 0x0f, 0xc4, 0x0c, 0x2f, 0x3f, 0x7a, 0x3b, 0xb8, 0x14, 0xa2, 0x57, 0x60,
	0xe6, 0x17, 0xd2, 0xb1, 0xb5, 0xfe, 0xc9, 0x3f, 0xf4, 0xef, 0xa6, 0x09, 0xd9, 0x34, 0xc8, 0x2f,
	0x64, 0x08, 0x60, 0xd5, 0x40, 0xf3, 0x87, 0x01, 0xb0, 0xbe, 0x28, 0xea, 0x03, 0x4c, 0x04, 0x2f,
	0x88, 0x1a, 0x91, 0xa9, 0xd4, 0xd3, 0xb4, 0xdb, 0xe7, 0xff, 0xd7, 0xa4, 0x8f, 0x89, 0x12, 0x8b,
	0xde, 0x0e, 0xde, 0x70, 0x68, 0x74, 0x61, 0x5f, 0x1f, 0xa3, 0x13, 0xb0, 0x45, 0x19, 0x44, 0x29,
	0x9f, 0x32, 0xa5, 0x9d, 0x0f, 0x31, 0xe8, 0xa3, 0x6e, 0x79, 0x82, 0x1e, 0x80, 0xc5, 0x59, 0x94,
	0xf2, 0x8c, 0x48, 0x67, 0xd7, 0x35, 0xbd, 0x43, 0x7c, 0xc0, 0x59, 0xb7, 0xfc, 0x0c, 0x6f, 0x6d,
	0x5e, 0xb1, 0xa9, 0xc0, 0xaa, 0xc7, 0x83, 0x9e, 0xc2, 0x31, 0x65, 0x7a, 0x44, 0x24, 0x92, 0x39,
	0x9d, 0x44, 0x33, 0x22, 0xe8, 0xd5, 0x42, 0xdb, 0x5b, 0x18, 0xd5, 0xb9, 0x41, 0x4e, 0x27, 0x1f,
	0x75, 0x06, 0x75, 0xc0, 0xae, 0xfa, 0x88, 0xf4, 0xbe, 0xee, 0x6e, 0xdb, 0x57, 0xa8, 0xc8, 0x7e,
	0x5c, 0x90, 0xb3, 0x87, 0x60, 0xd5, 0x9b, 0x88, 0x8e, 0xc0, 0xc6, 0x97, 0x1f, 0xfa, 0x6f, 0x22,
	0x7c, 0x19, 0xbe, 0xed, 0xdf, 0xd9, 0x49, 0x6e, 0xe8, 0x1f, 0xe2, 0xf9, 0x9f, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xd7, 0xc2, 0x98, 0x24, 0xbf, 0x03, 0x00, 0x00,
}
