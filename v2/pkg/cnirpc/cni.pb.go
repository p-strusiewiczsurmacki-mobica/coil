// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.27.2
// source: pkg/cnirpc/cni.proto

package cnirpc

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// ErrorCode enumerates errors for CNIError
type ErrorCode int32

const (
	ErrorCode_UNKNOWN                       ErrorCode = 0
	ErrorCode_INCOMPATIBLE_CNI_VERSION      ErrorCode = 1
	ErrorCode_UNSUPPORTED_FIELD             ErrorCode = 2
	ErrorCode_UNKNOWN_CONTAINER             ErrorCode = 3
	ErrorCode_INVALID_ENVIRONMENT_VARIABLES ErrorCode = 4
	ErrorCode_IO_FAILURE                    ErrorCode = 5
	ErrorCode_DECODING_FAILURE              ErrorCode = 6
	ErrorCode_INVALID_NETWORK_CONFIG        ErrorCode = 7
	ErrorCode_TRY_AGAIN_LATER               ErrorCode = 11
	ErrorCode_INTERNAL                      ErrorCode = 999
)

// Enum value maps for ErrorCode.
var (
	ErrorCode_name = map[int32]string{
		0:   "UNKNOWN",
		1:   "INCOMPATIBLE_CNI_VERSION",
		2:   "UNSUPPORTED_FIELD",
		3:   "UNKNOWN_CONTAINER",
		4:   "INVALID_ENVIRONMENT_VARIABLES",
		5:   "IO_FAILURE",
		6:   "DECODING_FAILURE",
		7:   "INVALID_NETWORK_CONFIG",
		11:  "TRY_AGAIN_LATER",
		999: "INTERNAL",
	}
	ErrorCode_value = map[string]int32{
		"UNKNOWN":                       0,
		"INCOMPATIBLE_CNI_VERSION":      1,
		"UNSUPPORTED_FIELD":             2,
		"UNKNOWN_CONTAINER":             3,
		"INVALID_ENVIRONMENT_VARIABLES": 4,
		"IO_FAILURE":                    5,
		"DECODING_FAILURE":              6,
		"INVALID_NETWORK_CONFIG":        7,
		"TRY_AGAIN_LATER":               11,
		"INTERNAL":                      999,
	}
)

func (x ErrorCode) Enum() *ErrorCode {
	p := new(ErrorCode)
	*p = x
	return p
}

func (x ErrorCode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ErrorCode) Descriptor() protoreflect.EnumDescriptor {
	return file_pkg_cnirpc_cni_proto_enumTypes[0].Descriptor()
}

func (ErrorCode) Type() protoreflect.EnumType {
	return &file_pkg_cnirpc_cni_proto_enumTypes[0]
}

func (x ErrorCode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ErrorCode.Descriptor instead.
func (ErrorCode) EnumDescriptor() ([]byte, []int) {
	return file_pkg_cnirpc_cni_proto_rawDescGZIP(), []int{0}
}

// CNIArgs is a mirror of cni.pkg.skel.CmdArgs struct.
// https://pkg.go.dev/github.com/containernetworking/cni@v0.8.0/pkg/skel?tab=doc#CmdArgs
type CNIArgs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ContainerId string            `protobuf:"bytes,1,opt,name=container_id,json=containerId,proto3" json:"container_id,omitempty"`
	Netns       string            `protobuf:"bytes,2,opt,name=netns,proto3" json:"netns,omitempty"`
	Ifname      string            `protobuf:"bytes,3,opt,name=ifname,proto3" json:"ifname,omitempty"`
	Args        map[string]string `protobuf:"bytes,4,rep,name=args,proto3" json:"args,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"` // Key-Value pairs parsed from CNI_ARGS
	Path        string            `protobuf:"bytes,5,opt,name=path,proto3" json:"path,omitempty"`
	StdinData   []byte            `protobuf:"bytes,6,opt,name=stdin_data,json=stdinData,proto3" json:"stdin_data,omitempty"`
	Ips         string            `protobuf:"bytes,7,opt,name=ips,proto3" json:"ips,omitempty"`
	Interfaces  map[string]bool   `protobuf:"bytes,8,rep,name=interfaces,proto3" json:"interfaces,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
}

func (x *CNIArgs) Reset() {
	*x = CNIArgs{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_cnirpc_cni_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CNIArgs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CNIArgs) ProtoMessage() {}

func (x *CNIArgs) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_cnirpc_cni_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CNIArgs.ProtoReflect.Descriptor instead.
func (*CNIArgs) Descriptor() ([]byte, []int) {
	return file_pkg_cnirpc_cni_proto_rawDescGZIP(), []int{0}
}

func (x *CNIArgs) GetContainerId() string {
	if x != nil {
		return x.ContainerId
	}
	return ""
}

func (x *CNIArgs) GetNetns() string {
	if x != nil {
		return x.Netns
	}
	return ""
}

func (x *CNIArgs) GetIfname() string {
	if x != nil {
		return x.Ifname
	}
	return ""
}

func (x *CNIArgs) GetArgs() map[string]string {
	if x != nil {
		return x.Args
	}
	return nil
}

func (x *CNIArgs) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *CNIArgs) GetStdinData() []byte {
	if x != nil {
		return x.StdinData
	}
	return nil
}

func (x *CNIArgs) GetIps() string {
	if x != nil {
		return x.Ips
	}
	return ""
}

func (x *CNIArgs) GetInterfaces() map[string]bool {
	if x != nil {
		return x.Interfaces
	}
	return nil
}

// CNIError is a mirror of cin.pkg.types.Error struct.
// https://pkg.go.dev/github.com/containernetworking/cni@v0.8.0/pkg/types?tab=doc#Error
//
// This should be added to *grpc.Status by WithDetails()
// https://pkg.go.dev/google.golang.org/grpc@v1.31.0/internal/status?tab=doc#Status.WithDetails
type CNIError struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Code    ErrorCode `protobuf:"varint,1,opt,name=code,proto3,enum=pkg.cnirpc.ErrorCode" json:"code,omitempty"`
	Msg     string    `protobuf:"bytes,2,opt,name=msg,proto3" json:"msg,omitempty"`
	Details string    `protobuf:"bytes,3,opt,name=details,proto3" json:"details,omitempty"`
}

func (x *CNIError) Reset() {
	*x = CNIError{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_cnirpc_cni_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CNIError) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CNIError) ProtoMessage() {}

func (x *CNIError) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_cnirpc_cni_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CNIError.ProtoReflect.Descriptor instead.
func (*CNIError) Descriptor() ([]byte, []int) {
	return file_pkg_cnirpc_cni_proto_rawDescGZIP(), []int{1}
}

func (x *CNIError) GetCode() ErrorCode {
	if x != nil {
		return x.Code
	}
	return ErrorCode_UNKNOWN
}

func (x *CNIError) GetMsg() string {
	if x != nil {
		return x.Msg
	}
	return ""
}

func (x *CNIError) GetDetails() string {
	if x != nil {
		return x.Details
	}
	return ""
}

// AddResponse represents the response for ADD command.
//
// `result` is a types.current.Result serialized into JSON.
// https://pkg.go.dev/github.com/containernetworking/cni@v0.8.0/pkg/types/current?tab=doc#Result
type AddResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Result []byte `protobuf:"bytes,1,opt,name=result,proto3" json:"result,omitempty"`
}

func (x *AddResponse) Reset() {
	*x = AddResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pkg_cnirpc_cni_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AddResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AddResponse) ProtoMessage() {}

func (x *AddResponse) ProtoReflect() protoreflect.Message {
	mi := &file_pkg_cnirpc_cni_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AddResponse.ProtoReflect.Descriptor instead.
func (*AddResponse) Descriptor() ([]byte, []int) {
	return file_pkg_cnirpc_cni_proto_rawDescGZIP(), []int{2}
}

func (x *AddResponse) GetResult() []byte {
	if x != nil {
		return x.Result
	}
	return nil
}

var File_pkg_cnirpc_cni_proto protoreflect.FileDescriptor

var file_pkg_cnirpc_cni_proto_rawDesc = []byte{
	0x0a, 0x14, 0x70, 0x6b, 0x67, 0x2f, 0x63, 0x6e, 0x69, 0x72, 0x70, 0x63, 0x2f, 0x63, 0x6e, 0x69,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x70, 0x6b, 0x67, 0x2e, 0x63, 0x6e, 0x69, 0x72,
	0x70, 0x63, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x8f, 0x03, 0x0a, 0x07, 0x43, 0x4e, 0x49, 0x41, 0x72, 0x67, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x63,
	0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x64, 0x12, 0x14,
	0x0a, 0x05, 0x6e, 0x65, 0x74, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6e,
	0x65, 0x74, 0x6e, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x69, 0x66, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x69, 0x66, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x31, 0x0a, 0x04,
	0x61, 0x72, 0x67, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x70, 0x6b, 0x67,
	0x2e, 0x63, 0x6e, 0x69, 0x72, 0x70, 0x63, 0x2e, 0x43, 0x4e, 0x49, 0x41, 0x72, 0x67, 0x73, 0x2e,
	0x41, 0x72, 0x67, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x04, 0x61, 0x72, 0x67, 0x73, 0x12,
	0x12, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70,
	0x61, 0x74, 0x68, 0x12, 0x1d, 0x0a, 0x0a, 0x73, 0x74, 0x64, 0x69, 0x6e, 0x5f, 0x64, 0x61, 0x74,
	0x61, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x74, 0x64, 0x69, 0x6e, 0x44, 0x61,
	0x74, 0x61, 0x12, 0x10, 0x0a, 0x03, 0x69, 0x70, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x69, 0x70, 0x73, 0x12, 0x43, 0x0a, 0x0a, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63,
	0x65, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x63,
	0x6e, 0x69, 0x72, 0x70, 0x63, 0x2e, 0x43, 0x4e, 0x49, 0x41, 0x72, 0x67, 0x73, 0x2e, 0x49, 0x6e,
	0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a, 0x69,
	0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73, 0x1a, 0x37, 0x0a, 0x09, 0x41, 0x72, 0x67,
	0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02,
	0x38, 0x01, 0x1a, 0x3d, 0x0a, 0x0f, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x22, 0x61, 0x0a, 0x08, 0x43, 0x4e, 0x49, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x29, 0x0a,
	0x04, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15, 0x2e, 0x70, 0x6b,
	0x67, 0x2e, 0x63, 0x6e, 0x69, 0x72, 0x70, 0x63, 0x2e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f,
	0x64, 0x65, 0x52, 0x04, 0x63, 0x6f, 0x64, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6d, 0x73, 0x67, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6d, 0x73, 0x67, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x65,
	0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x64, 0x65, 0x74,
	0x61, 0x69, 0x6c, 0x73, 0x22, 0x25, 0x0a, 0x0b, 0x41, 0x64, 0x64, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x2a, 0xed, 0x01, 0x0a, 0x09,
	0x45, 0x72, 0x72, 0x6f, 0x72, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x55, 0x4e, 0x4b,
	0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x1c, 0x0a, 0x18, 0x49, 0x4e, 0x43, 0x4f, 0x4d, 0x50,
	0x41, 0x54, 0x49, 0x42, 0x4c, 0x45, 0x5f, 0x43, 0x4e, 0x49, 0x5f, 0x56, 0x45, 0x52, 0x53, 0x49,
	0x4f, 0x4e, 0x10, 0x01, 0x12, 0x15, 0x0a, 0x11, 0x55, 0x4e, 0x53, 0x55, 0x50, 0x50, 0x4f, 0x52,
	0x54, 0x45, 0x44, 0x5f, 0x46, 0x49, 0x45, 0x4c, 0x44, 0x10, 0x02, 0x12, 0x15, 0x0a, 0x11, 0x55,
	0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x5f, 0x43, 0x4f, 0x4e, 0x54, 0x41, 0x49, 0x4e, 0x45, 0x52,
	0x10, 0x03, 0x12, 0x21, 0x0a, 0x1d, 0x49, 0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x5f, 0x45, 0x4e,
	0x56, 0x49, 0x52, 0x4f, 0x4e, 0x4d, 0x45, 0x4e, 0x54, 0x5f, 0x56, 0x41, 0x52, 0x49, 0x41, 0x42,
	0x4c, 0x45, 0x53, 0x10, 0x04, 0x12, 0x0e, 0x0a, 0x0a, 0x49, 0x4f, 0x5f, 0x46, 0x41, 0x49, 0x4c,
	0x55, 0x52, 0x45, 0x10, 0x05, 0x12, 0x14, 0x0a, 0x10, 0x44, 0x45, 0x43, 0x4f, 0x44, 0x49, 0x4e,
	0x47, 0x5f, 0x46, 0x41, 0x49, 0x4c, 0x55, 0x52, 0x45, 0x10, 0x06, 0x12, 0x1a, 0x0a, 0x16, 0x49,
	0x4e, 0x56, 0x41, 0x4c, 0x49, 0x44, 0x5f, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x5f, 0x43,
	0x4f, 0x4e, 0x46, 0x49, 0x47, 0x10, 0x07, 0x12, 0x13, 0x0a, 0x0f, 0x54, 0x52, 0x59, 0x5f, 0x41,
	0x47, 0x41, 0x49, 0x4e, 0x5f, 0x4c, 0x41, 0x54, 0x45, 0x52, 0x10, 0x0b, 0x12, 0x0d, 0x0a, 0x08,
	0x49, 0x4e, 0x54, 0x45, 0x52, 0x4e, 0x41, 0x4c, 0x10, 0xe7, 0x07, 0x32, 0xa4, 0x01, 0x0a, 0x03,
	0x43, 0x4e, 0x49, 0x12, 0x33, 0x0a, 0x03, 0x41, 0x64, 0x64, 0x12, 0x13, 0x2e, 0x70, 0x6b, 0x67,
	0x2e, 0x63, 0x6e, 0x69, 0x72, 0x70, 0x63, 0x2e, 0x43, 0x4e, 0x49, 0x41, 0x72, 0x67, 0x73, 0x1a,
	0x17, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x63, 0x6e, 0x69, 0x72, 0x70, 0x63, 0x2e, 0x41, 0x64, 0x64,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x32, 0x0a, 0x03, 0x44, 0x65, 0x6c, 0x12,
	0x13, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x63, 0x6e, 0x69, 0x72, 0x70, 0x63, 0x2e, 0x43, 0x4e, 0x49,
	0x41, 0x72, 0x67, 0x73, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x34, 0x0a, 0x05,
	0x43, 0x68, 0x65, 0x63, 0x6b, 0x12, 0x13, 0x2e, 0x70, 0x6b, 0x67, 0x2e, 0x63, 0x6e, 0x69, 0x72,
	0x70, 0x63, 0x2e, 0x43, 0x4e, 0x49, 0x41, 0x72, 0x67, 0x73, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x42, 0x29, 0x5a, 0x27, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x63, 0x79, 0x62, 0x6f, 0x7a, 0x75, 0x2d, 0x67, 0x6f, 0x2f, 0x63, 0x6f, 0x69, 0x6c, 0x2f,
	0x76, 0x32, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x63, 0x6e, 0x69, 0x72, 0x70, 0x63, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pkg_cnirpc_cni_proto_rawDescOnce sync.Once
	file_pkg_cnirpc_cni_proto_rawDescData = file_pkg_cnirpc_cni_proto_rawDesc
)

func file_pkg_cnirpc_cni_proto_rawDescGZIP() []byte {
	file_pkg_cnirpc_cni_proto_rawDescOnce.Do(func() {
		file_pkg_cnirpc_cni_proto_rawDescData = protoimpl.X.CompressGZIP(file_pkg_cnirpc_cni_proto_rawDescData)
	})
	return file_pkg_cnirpc_cni_proto_rawDescData
}

var file_pkg_cnirpc_cni_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_pkg_cnirpc_cni_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_pkg_cnirpc_cni_proto_goTypes = []any{
	(ErrorCode)(0),        // 0: pkg.cnirpc.ErrorCode
	(*CNIArgs)(nil),       // 1: pkg.cnirpc.CNIArgs
	(*CNIError)(nil),      // 2: pkg.cnirpc.CNIError
	(*AddResponse)(nil),   // 3: pkg.cnirpc.AddResponse
	nil,                   // 4: pkg.cnirpc.CNIArgs.ArgsEntry
	nil,                   // 5: pkg.cnirpc.CNIArgs.InterfacesEntry
	(*emptypb.Empty)(nil), // 6: google.protobuf.Empty
}
var file_pkg_cnirpc_cni_proto_depIdxs = []int32{
	4, // 0: pkg.cnirpc.CNIArgs.args:type_name -> pkg.cnirpc.CNIArgs.ArgsEntry
	5, // 1: pkg.cnirpc.CNIArgs.interfaces:type_name -> pkg.cnirpc.CNIArgs.InterfacesEntry
	0, // 2: pkg.cnirpc.CNIError.code:type_name -> pkg.cnirpc.ErrorCode
	1, // 3: pkg.cnirpc.CNI.Add:input_type -> pkg.cnirpc.CNIArgs
	1, // 4: pkg.cnirpc.CNI.Del:input_type -> pkg.cnirpc.CNIArgs
	1, // 5: pkg.cnirpc.CNI.Check:input_type -> pkg.cnirpc.CNIArgs
	3, // 6: pkg.cnirpc.CNI.Add:output_type -> pkg.cnirpc.AddResponse
	6, // 7: pkg.cnirpc.CNI.Del:output_type -> google.protobuf.Empty
	6, // 8: pkg.cnirpc.CNI.Check:output_type -> google.protobuf.Empty
	6, // [6:9] is the sub-list for method output_type
	3, // [3:6] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_pkg_cnirpc_cni_proto_init() }
func file_pkg_cnirpc_cni_proto_init() {
	if File_pkg_cnirpc_cni_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pkg_cnirpc_cni_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*CNIArgs); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_cnirpc_cni_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*CNIError); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_pkg_cnirpc_cni_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*AddResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pkg_cnirpc_cni_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_pkg_cnirpc_cni_proto_goTypes,
		DependencyIndexes: file_pkg_cnirpc_cni_proto_depIdxs,
		EnumInfos:         file_pkg_cnirpc_cni_proto_enumTypes,
		MessageInfos:      file_pkg_cnirpc_cni_proto_msgTypes,
	}.Build()
	File_pkg_cnirpc_cni_proto = out.File
	file_pkg_cnirpc_cni_proto_rawDesc = nil
	file_pkg_cnirpc_cni_proto_goTypes = nil
	file_pkg_cnirpc_cni_proto_depIdxs = nil
}
