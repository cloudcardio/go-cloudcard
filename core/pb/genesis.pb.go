// Code generated by protoc-gen-go. DO NOT EDIT.
// source: genesis.proto

package corepb

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Genesis struct {
	ChainId                uint32               `protobuf:"varint,1,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"`
	SuperNodes             []*TokenDistribution `protobuf:"bytes,2,rep,name=super_nodes,json=superNodes,proto3" json:"super_nodes,omitempty"`
	StandbyNodes           []*TokenDistribution `protobuf:"bytes,3,rep,name=standby_nodes,json=standbyNodes,proto3" json:"standby_nodes,omitempty"`
	Foundation             *TokenDistribution   `protobuf:"bytes,4,opt,name=foundation,proto3" json:"foundation,omitempty"`
	FoundingTeam           *TokenDistribution   `protobuf:"bytes,5,opt,name=founding_team,json=foundingTeam,proto3" json:"founding_team,omitempty"`
	NodeDeployment         *TokenDistribution   `protobuf:"bytes,6,opt,name=node_deployment,json=nodeDeployment,proto3" json:"node_deployment,omitempty"`
	FoundingCommunity      *TokenDistribution   `protobuf:"bytes,7,opt,name=founding_community,json=foundingCommunity,proto3" json:"founding_community,omitempty"`
	EcologicalConstruction *TokenDistribution   `protobuf:"bytes,8,opt,name=ecological_construction,json=ecologicalConstruction,proto3" json:"ecological_construction,omitempty"`
	XXX_NoUnkeyedLiteral   struct{}             `json:"-"`
	XXX_unrecognized       []byte               `json:"-"`
	XXX_sizecache          int32                `json:"-"`
}

func (m *Genesis) Reset()         { *m = Genesis{} }
func (m *Genesis) String() string { return proto.CompactTextString(m) }
func (*Genesis) ProtoMessage()    {}
func (*Genesis) Descriptor() ([]byte, []int) {
	return fileDescriptor_14205810582f3203, []int{0}
}

func (m *Genesis) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Genesis.Unmarshal(m, b)
}
func (m *Genesis) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Genesis.Marshal(b, m, deterministic)
}
func (m *Genesis) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Genesis.Merge(m, src)
}
func (m *Genesis) XXX_Size() int {
	return xxx_messageInfo_Genesis.Size(m)
}
func (m *Genesis) XXX_DiscardUnknown() {
	xxx_messageInfo_Genesis.DiscardUnknown(m)
}

var xxx_messageInfo_Genesis proto.InternalMessageInfo

func (m *Genesis) GetChainId() uint32 {
	if m != nil {
		return m.ChainId
	}
	return 0
}

func (m *Genesis) GetSuperNodes() []*TokenDistribution {
	if m != nil {
		return m.SuperNodes
	}
	return nil
}

func (m *Genesis) GetStandbyNodes() []*TokenDistribution {
	if m != nil {
		return m.StandbyNodes
	}
	return nil
}

func (m *Genesis) GetFoundation() *TokenDistribution {
	if m != nil {
		return m.Foundation
	}
	return nil
}

func (m *Genesis) GetFoundingTeam() *TokenDistribution {
	if m != nil {
		return m.FoundingTeam
	}
	return nil
}

func (m *Genesis) GetNodeDeployment() *TokenDistribution {
	if m != nil {
		return m.NodeDeployment
	}
	return nil
}

func (m *Genesis) GetFoundingCommunity() *TokenDistribution {
	if m != nil {
		return m.FoundingCommunity
	}
	return nil
}

func (m *Genesis) GetEcologicalConstruction() *TokenDistribution {
	if m != nil {
		return m.EcologicalConstruction
	}
	return nil
}

type TokenDistribution struct {
	Address              string   `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Value                string   `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TokenDistribution) Reset()         { *m = TokenDistribution{} }
func (m *TokenDistribution) String() string { return proto.CompactTextString(m) }
func (*TokenDistribution) ProtoMessage()    {}
func (*TokenDistribution) Descriptor() ([]byte, []int) {
	return fileDescriptor_14205810582f3203, []int{1}
}

func (m *TokenDistribution) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TokenDistribution.Unmarshal(m, b)
}
func (m *TokenDistribution) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TokenDistribution.Marshal(b, m, deterministic)
}
func (m *TokenDistribution) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TokenDistribution.Merge(m, src)
}
func (m *TokenDistribution) XXX_Size() int {
	return xxx_messageInfo_TokenDistribution.Size(m)
}
func (m *TokenDistribution) XXX_DiscardUnknown() {
	xxx_messageInfo_TokenDistribution.DiscardUnknown(m)
}

var xxx_messageInfo_TokenDistribution proto.InternalMessageInfo

func (m *TokenDistribution) GetAddress() string {
	if m != nil {
		return m.Address
	}
	return ""
}

func (m *TokenDistribution) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

type StandByNodes struct {
	StandbyNodes         []string `protobuf:"bytes,1,rep,name=standby_nodes,json=standbyNodes,proto3" json:"standby_nodes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StandByNodes) Reset()         { *m = StandByNodes{} }
func (m *StandByNodes) String() string { return proto.CompactTextString(m) }
func (*StandByNodes) ProtoMessage()    {}
func (*StandByNodes) Descriptor() ([]byte, []int) {
	return fileDescriptor_14205810582f3203, []int{2}
}

func (m *StandByNodes) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StandByNodes.Unmarshal(m, b)
}
func (m *StandByNodes) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StandByNodes.Marshal(b, m, deterministic)
}
func (m *StandByNodes) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StandByNodes.Merge(m, src)
}
func (m *StandByNodes) XXX_Size() int {
	return xxx_messageInfo_StandByNodes.Size(m)
}
func (m *StandByNodes) XXX_DiscardUnknown() {
	xxx_messageInfo_StandByNodes.DiscardUnknown(m)
}

var xxx_messageInfo_StandByNodes proto.InternalMessageInfo

func (m *StandByNodes) GetStandbyNodes() []string {
	if m != nil {
		return m.StandbyNodes
	}
	return nil
}

type SuperNodes struct {
	SuperNodes           []string `protobuf:"bytes,1,rep,name=super_nodes,json=superNodes,proto3" json:"super_nodes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SuperNodes) Reset()         { *m = SuperNodes{} }
func (m *SuperNodes) String() string { return proto.CompactTextString(m) }
func (*SuperNodes) ProtoMessage()    {}
func (*SuperNodes) Descriptor() ([]byte, []int) {
	return fileDescriptor_14205810582f3203, []int{3}
}

func (m *SuperNodes) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SuperNodes.Unmarshal(m, b)
}
func (m *SuperNodes) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SuperNodes.Marshal(b, m, deterministic)
}
func (m *SuperNodes) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SuperNodes.Merge(m, src)
}
func (m *SuperNodes) XXX_Size() int {
	return xxx_messageInfo_SuperNodes.Size(m)
}
func (m *SuperNodes) XXX_DiscardUnknown() {
	xxx_messageInfo_SuperNodes.DiscardUnknown(m)
}

var xxx_messageInfo_SuperNodes proto.InternalMessageInfo

func (m *SuperNodes) GetSuperNodes() []string {
	if m != nil {
		return m.SuperNodes
	}
	return nil
}

func init() {
	proto.RegisterType((*Genesis)(nil), "corepb.Genesis")
	proto.RegisterType((*TokenDistribution)(nil), "corepb.TokenDistribution")
	proto.RegisterType((*StandByNodes)(nil), "corepb.StandByNodes")
	proto.RegisterType((*SuperNodes)(nil), "corepb.SuperNodes")
}

func init() { proto.RegisterFile("genesis.proto", fileDescriptor_14205810582f3203) }

var fileDescriptor_14205810582f3203 = []byte{
	// 339 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0xc1, 0x4f, 0xfa, 0x30,
	0x1c, 0xc5, 0x33, 0xf6, 0x83, 0xc1, 0x17, 0xf8, 0x19, 0x1a, 0xa3, 0xe5, 0xe4, 0x32, 0x2f, 0x5c,
	0xe4, 0x20, 0x27, 0x3d, 0x78, 0x00, 0x12, 0xf5, 0xe2, 0x61, 0x70, 0x5f, 0xba, 0xb6, 0x62, 0xe3,
	0xd6, 0x2e, 0x6b, 0x67, 0xc2, 0x1f, 0x6f, 0x62, 0xd6, 0x31, 0x06, 0x7a, 0xd8, 0xf1, 0xad, 0xef,
	0xf3, 0xda, 0xec, 0x3d, 0x18, 0xef, 0xb8, 0xe4, 0x5a, 0xe8, 0x79, 0x96, 0x2b, 0xa3, 0x50, 0x8f,
	0xaa, 0x9c, 0x67, 0x71, 0xf0, 0xed, 0x82, 0xf7, 0x5c, 0x9d, 0xa0, 0x29, 0xf4, 0xe9, 0x07, 0x11,
	0x32, 0x12, 0x0c, 0x3b, 0xbe, 0x33, 0x1b, 0x87, 0x9e, 0xd5, 0xaf, 0x0c, 0x3d, 0xc2, 0x50, 0x17,
	0x19, 0xcf, 0x23, 0xa9, 0x18, 0xd7, 0xb8, 0xe3, 0xbb, 0xb3, 0xe1, 0xfd, 0x74, 0x5e, 0x85, 0xcc,
	0xb7, 0xea, 0x93, 0xcb, 0xb5, 0xd0, 0x26, 0x17, 0x71, 0x61, 0x84, 0x92, 0x21, 0x58, 0xf7, 0x5b,
	0x69, 0x46, 0x4f, 0x30, 0xd6, 0x86, 0x48, 0x16, 0xef, 0x0f, 0xb4, 0xdb, 0x46, 0x8f, 0x0e, 0xfe,
	0x8a, 0x7f, 0x00, 0x78, 0x57, 0x85, 0x64, 0xa4, 0x3c, 0xc3, 0xff, 0x7c, 0xa7, 0xe5, 0xea, 0xc6,
	0x5c, 0x5e, 0x6d, 0x95, 0x90, 0xbb, 0xc8, 0x70, 0x92, 0xe2, 0x6e, 0x1b, 0x3d, 0xaa, 0xfd, 0x5b,
	0x4e, 0x52, 0xb4, 0x84, 0x8b, 0xf2, 0xc9, 0x11, 0xe3, 0x59, 0xa2, 0xf6, 0x29, 0x97, 0x06, 0xf7,
	0xda, 0x12, 0xfe, 0x97, 0xc4, 0xfa, 0x08, 0xa0, 0x17, 0x40, 0xc7, 0x37, 0x50, 0x95, 0xa6, 0x85,
	0x14, 0x66, 0x8f, 0xbd, 0xb6, 0x98, 0x49, 0x0d, 0xad, 0x6a, 0x06, 0x85, 0x70, 0xcd, 0xa9, 0x4a,
	0xd4, 0x4e, 0x50, 0x92, 0x44, 0x54, 0x49, 0x6d, 0xf2, 0x82, 0xda, 0xbf, 0xd2, 0x6f, 0x8b, 0xbb,
	0x6a, 0xc8, 0xd5, 0x09, 0x18, 0xac, 0x60, 0xf2, 0xc7, 0x8c, 0x30, 0x78, 0x84, 0xb1, 0x9c, 0x6b,
	0x6d, 0x77, 0x30, 0x08, 0x6b, 0x89, 0x2e, 0xa1, 0xfb, 0x45, 0x92, 0x82, 0xe3, 0x8e, 0xfd, 0x5e,
	0x89, 0x60, 0x01, 0xa3, 0x4d, 0xd9, 0xd8, 0xf2, 0xd0, 0xd8, 0xed, 0xef, 0xc6, 0x1d, 0xdf, 0x9d,
	0x0d, 0xce, 0x6b, 0x0d, 0xee, 0x00, 0x36, 0xcd, 0x48, 0x6e, 0xce, 0x07, 0x56, 0x01, 0x27, 0x2b,
	0x8a, 0x7b, 0x76, 0xb7, 0x8b, 0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x64, 0x90, 0xa5, 0x4a, 0xc8,
	0x02, 0x00, 0x00,
}
