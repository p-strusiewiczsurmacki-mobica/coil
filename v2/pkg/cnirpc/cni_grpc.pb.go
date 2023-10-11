// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.23.4
// source: pkg/cnirpc/cni.proto

package cnirpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	CNI_Add_FullMethodName   = "/pkg.cnirpc.CNI/Add"
	CNI_Del_FullMethodName   = "/pkg.cnirpc.CNI/Del"
	CNI_Check_FullMethodName = "/pkg.cnirpc.CNI/Check"
)

// CNIClient is the client API for CNI service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CNIClient interface {
	Add(ctx context.Context, in *CNIArgs, opts ...grpc.CallOption) (*AddResponse, error)
	Del(ctx context.Context, in *CNIArgs, opts ...grpc.CallOption) (*emptypb.Empty, error)
	Check(ctx context.Context, in *CNIArgs, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type cNIClient struct {
	cc grpc.ClientConnInterface
}

func NewCNIClient(cc grpc.ClientConnInterface) CNIClient {
	return &cNIClient{cc}
}

func (c *cNIClient) Add(ctx context.Context, in *CNIArgs, opts ...grpc.CallOption) (*AddResponse, error) {
	out := new(AddResponse)
	err := c.cc.Invoke(ctx, CNI_Add_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cNIClient) Del(ctx context.Context, in *CNIArgs, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, CNI_Del_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cNIClient) Check(ctx context.Context, in *CNIArgs, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, CNI_Check_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CNIServer is the server API for CNI service.
// All implementations must embed UnimplementedCNIServer
// for forward compatibility
type CNIServer interface {
	Add(context.Context, *CNIArgs) (*AddResponse, error)
	Del(context.Context, *CNIArgs) (*emptypb.Empty, error)
	Check(context.Context, *CNIArgs) (*emptypb.Empty, error)
	mustEmbedUnimplementedCNIServer()
}

// UnimplementedCNIServer must be embedded to have forward compatible implementations.
type UnimplementedCNIServer struct {
}

func (UnimplementedCNIServer) Add(context.Context, *CNIArgs) (*AddResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Add not implemented")
}
func (UnimplementedCNIServer) Del(context.Context, *CNIArgs) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Del not implemented")
}
func (UnimplementedCNIServer) Check(context.Context, *CNIArgs) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Check not implemented")
}
func (UnimplementedCNIServer) mustEmbedUnimplementedCNIServer() {}

// UnsafeCNIServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CNIServer will
// result in compilation errors.
type UnsafeCNIServer interface {
	mustEmbedUnimplementedCNIServer()
}

func RegisterCNIServer(s grpc.ServiceRegistrar, srv CNIServer) {
	s.RegisterService(&CNI_ServiceDesc, srv)
}

func _CNI_Add_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CNIArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CNIServer).Add(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CNI_Add_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CNIServer).Add(ctx, req.(*CNIArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _CNI_Del_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CNIArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CNIServer).Del(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CNI_Del_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CNIServer).Del(ctx, req.(*CNIArgs))
	}
	return interceptor(ctx, in, info, handler)
}

func _CNI_Check_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CNIArgs)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CNIServer).Check(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CNI_Check_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CNIServer).Check(ctx, req.(*CNIArgs))
	}
	return interceptor(ctx, in, info, handler)
}

// CNI_ServiceDesc is the grpc.ServiceDesc for CNI service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CNI_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "pkg.cnirpc.CNI",
	HandlerType: (*CNIServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Add",
			Handler:    _CNI_Add_Handler,
		},
		{
			MethodName: "Del",
			Handler:    _CNI_Del_Handler,
		},
		{
			MethodName: "Check",
			Handler:    _CNI_Check_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pkg/cnirpc/cni.proto",
}
