// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.19.4
// source: common/conf/server.proto

package conf

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type Server struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Http *Server_HTTP `protobuf:"bytes,1,opt,name=http,proto3" json:"http,omitempty"`
	Grpc *Server_GRPC `protobuf:"bytes,2,opt,name=grpc,proto3" json:"grpc,omitempty"`
}

func (x *Server) Reset() {
	*x = Server{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_conf_server_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Server) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Server) ProtoMessage() {}

func (x *Server) ProtoReflect() protoreflect.Message {
	mi := &file_common_conf_server_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Server.ProtoReflect.Descriptor instead.
func (*Server) Descriptor() ([]byte, []int) {
	return file_common_conf_server_proto_rawDescGZIP(), []int{0}
}

func (x *Server) GetHttp() *Server_HTTP {
	if x != nil {
		return x.Http
	}
	return nil
}

func (x *Server) GetGrpc() *Server_GRPC {
	if x != nil {
		return x.Grpc
	}
	return nil
}

// HTTP
type Server_HTTP struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Network string               `protobuf:"bytes,1,opt,name=network,proto3" json:"network,omitempty"`
	Addr    string               `protobuf:"bytes,2,opt,name=addr,proto3" json:"addr,omitempty"`
	Timeout *durationpb.Duration `protobuf:"bytes,3,opt,name=timeout,proto3" json:"timeout,omitempty"`
	Headers []string             `protobuf:"bytes,4,rep,name=headers,proto3" json:"headers,omitempty"`
	Methods []string             `protobuf:"bytes,5,rep,name=methods,proto3" json:"methods,omitempty"`
	Origins []string             `protobuf:"bytes,6,rep,name=origins,proto3" json:"origins,omitempty"`
}

func (x *Server_HTTP) Reset() {
	*x = Server_HTTP{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_conf_server_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Server_HTTP) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Server_HTTP) ProtoMessage() {}

func (x *Server_HTTP) ProtoReflect() protoreflect.Message {
	mi := &file_common_conf_server_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Server_HTTP.ProtoReflect.Descriptor instead.
func (*Server_HTTP) Descriptor() ([]byte, []int) {
	return file_common_conf_server_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Server_HTTP) GetNetwork() string {
	if x != nil {
		return x.Network
	}
	return ""
}

func (x *Server_HTTP) GetAddr() string {
	if x != nil {
		return x.Addr
	}
	return ""
}

func (x *Server_HTTP) GetTimeout() *durationpb.Duration {
	if x != nil {
		return x.Timeout
	}
	return nil
}

func (x *Server_HTTP) GetHeaders() []string {
	if x != nil {
		return x.Headers
	}
	return nil
}

func (x *Server_HTTP) GetMethods() []string {
	if x != nil {
		return x.Methods
	}
	return nil
}

func (x *Server_HTTP) GetOrigins() []string {
	if x != nil {
		return x.Origins
	}
	return nil
}

// gPRC
type Server_GRPC struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Network string               `protobuf:"bytes,1,opt,name=network,proto3" json:"network,omitempty"`
	Addr    string               `protobuf:"bytes,2,opt,name=addr,proto3" json:"addr,omitempty"`
	Timeout *durationpb.Duration `protobuf:"bytes,3,opt,name=timeout,proto3" json:"timeout,omitempty"`
}

func (x *Server_GRPC) Reset() {
	*x = Server_GRPC{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_conf_server_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Server_GRPC) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Server_GRPC) ProtoMessage() {}

func (x *Server_GRPC) ProtoReflect() protoreflect.Message {
	mi := &file_common_conf_server_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Server_GRPC.ProtoReflect.Descriptor instead.
func (*Server_GRPC) Descriptor() ([]byte, []int) {
	return file_common_conf_server_proto_rawDescGZIP(), []int{0, 1}
}

func (x *Server_GRPC) GetNetwork() string {
	if x != nil {
		return x.Network
	}
	return ""
}

func (x *Server_GRPC) GetAddr() string {
	if x != nil {
		return x.Addr
	}
	return ""
}

func (x *Server_GRPC) GetTimeout() *durationpb.Duration {
	if x != nil {
		return x.Timeout
	}
	return nil
}

var File_common_conf_server_proto protoreflect.FileDescriptor

var file_common_conf_server_proto_rawDesc = []byte{
	0x0a, 0x18, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x2f, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x89, 0x03, 0x0a, 0x06, 0x53, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x12, 0x2c, 0x0a, 0x04, 0x68, 0x74, 0x74, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x18, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x2e, 0x53,
	0x65, 0x72, 0x76, 0x65, 0x72, 0x2e, 0x48, 0x54, 0x54, 0x50, 0x52, 0x04, 0x68, 0x74, 0x74, 0x70,
	0x12, 0x2c, 0x0a, 0x04, 0x67, 0x72, 0x70, 0x63, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18,
	0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x2e, 0x53, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x2e, 0x47, 0x52, 0x50, 0x43, 0x52, 0x04, 0x67, 0x72, 0x70, 0x63, 0x1a, 0xb7,
	0x01, 0x0a, 0x04, 0x48, 0x54, 0x54, 0x50, 0x12, 0x18, 0x0a, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x12, 0x12, 0x0a, 0x04, 0x61, 0x64, 0x64, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x61, 0x64, 0x64, 0x72, 0x12, 0x33, 0x0a, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x68, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x68, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x18,
	0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x73, 0x12, 0x18,
	0x0a, 0x07, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x07, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x73, 0x1a, 0x69, 0x0a, 0x04, 0x47, 0x52, 0x50, 0x43,
	0x12, 0x18, 0x0a, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x12, 0x12, 0x0a, 0x04, 0x61, 0x64,
	0x64, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x61, 0x64, 0x64, 0x72, 0x12, 0x33,
	0x0a, 0x07, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x07, 0x74, 0x69, 0x6d, 0x65,
	0x6f, 0x75, 0x74, 0x42, 0x27, 0x5a, 0x25, 0x67, 0x6f, 0x2d, 0x63, 0x61, 0x73, 0x62, 0x69, 0x6e,
	0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x67, 0x6f, 0x2f, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x3b, 0x63, 0x6f, 0x6e, 0x66, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_common_conf_server_proto_rawDescOnce sync.Once
	file_common_conf_server_proto_rawDescData = file_common_conf_server_proto_rawDesc
)

func file_common_conf_server_proto_rawDescGZIP() []byte {
	file_common_conf_server_proto_rawDescOnce.Do(func() {
		file_common_conf_server_proto_rawDescData = protoimpl.X.CompressGZIP(file_common_conf_server_proto_rawDescData)
	})
	return file_common_conf_server_proto_rawDescData
}

var file_common_conf_server_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_common_conf_server_proto_goTypes = []interface{}{
	(*Server)(nil),              // 0: common.conf.Server
	(*Server_HTTP)(nil),         // 1: common.conf.Server.HTTP
	(*Server_GRPC)(nil),         // 2: common.conf.Server.GRPC
	(*durationpb.Duration)(nil), // 3: google.protobuf.Duration
}
var file_common_conf_server_proto_depIdxs = []int32{
	1, // 0: common.conf.Server.http:type_name -> common.conf.Server.HTTP
	2, // 1: common.conf.Server.grpc:type_name -> common.conf.Server.GRPC
	3, // 2: common.conf.Server.HTTP.timeout:type_name -> google.protobuf.Duration
	3, // 3: common.conf.Server.GRPC.timeout:type_name -> google.protobuf.Duration
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_common_conf_server_proto_init() }
func file_common_conf_server_proto_init() {
	if File_common_conf_server_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_common_conf_server_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Server); i {
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
		file_common_conf_server_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Server_HTTP); i {
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
		file_common_conf_server_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Server_GRPC); i {
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
			RawDescriptor: file_common_conf_server_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_common_conf_server_proto_goTypes,
		DependencyIndexes: file_common_conf_server_proto_depIdxs,
		MessageInfos:      file_common_conf_server_proto_msgTypes,
	}.Build()
	File_common_conf_server_proto = out.File
	file_common_conf_server_proto_rawDesc = nil
	file_common_conf_server_proto_goTypes = nil
	file_common_conf_server_proto_depIdxs = nil
}
