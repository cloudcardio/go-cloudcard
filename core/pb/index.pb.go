// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: index.proto

package corepb

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
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
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type ContractSet struct {
	NormalCons           uint64   `protobuf:"varint,1,opt,name=normal_cons,json=normalCons,proto3" json:"normal_cons,omitempty"`
	TemplateCons         uint64   `protobuf:"varint,2,opt,name=template_cons,json=templateCons,proto3" json:"template_cons,omitempty"`
	TemplateConsRefs     uint64   `protobuf:"varint,3,opt,name=template_cons_refs,json=templateConsRefs,proto3" json:"template_cons_refs,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ContractSet) Reset()         { *m = ContractSet{} }
func (m *ContractSet) String() string { return proto.CompactTextString(m) }
func (*ContractSet) ProtoMessage()    {}
func (*ContractSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_f750e0f7889345b5, []int{0}
}
func (m *ContractSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ContractSet.Unmarshal(m, b)
}
func (m *ContractSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ContractSet.Marshal(b, m, deterministic)
}
func (m *ContractSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContractSet.Merge(m, src)
}
func (m *ContractSet) XXX_Size() int {
	return xxx_messageInfo_ContractSet.Size(m)
}
func (m *ContractSet) XXX_DiscardUnknown() {
	xxx_messageInfo_ContractSet.DiscardUnknown(m)
}

var xxx_messageInfo_ContractSet proto.InternalMessageInfo

func (m *ContractSet) GetNormalCons() uint64 {
	if m != nil {
		return m.NormalCons
	}
	return 0
}

func (m *ContractSet) GetTemplateCons() uint64 {
	if m != nil {
		return m.TemplateCons
	}
	return 0
}

func (m *ContractSet) GetTemplateConsRefs() uint64 {
	if m != nil {
		return m.TemplateConsRefs
	}
	return 0
}

type TransactionSet struct {
	NormalTxs            uint64   `protobuf:"varint,1,opt,name=normal_txs,json=normalTxs,proto3" json:"normal_txs,omitempty"`
	ContractTxs          uint64   `protobuf:"varint,2,opt,name=contract_txs,json=contractTxs,proto3" json:"contract_txs,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *TransactionSet) Reset()         { *m = TransactionSet{} }
func (m *TransactionSet) String() string { return proto.CompactTextString(m) }
func (*TransactionSet) ProtoMessage()    {}
func (*TransactionSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_f750e0f7889345b5, []int{1}
}
func (m *TransactionSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TransactionSet.Unmarshal(m, b)
}
func (m *TransactionSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TransactionSet.Marshal(b, m, deterministic)
}
func (m *TransactionSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TransactionSet.Merge(m, src)
}
func (m *TransactionSet) XXX_Size() int {
	return xxx_messageInfo_TransactionSet.Size(m)
}
func (m *TransactionSet) XXX_DiscardUnknown() {
	xxx_messageInfo_TransactionSet.DiscardUnknown(m)
}

var xxx_messageInfo_TransactionSet proto.InternalMessageInfo

func (m *TransactionSet) GetNormalTxs() uint64 {
	if m != nil {
		return m.NormalTxs
	}
	return 0
}

func (m *TransactionSet) GetContractTxs() uint64 {
	if m != nil {
		return m.ContractTxs
	}
	return 0
}

type HandledData struct {
	PrevRoundProductions int32           `protobuf:"varint,1,opt,name=prev_round_productions,json=prevRoundProductions,proto3" json:"prev_round_productions,omitempty"`
	WinningTimes         uint64          `protobuf:"varint,2,opt,name=winningTimes,proto3" json:"winningTimes,omitempty"`
	HandledContracts     *ContractSet    `protobuf:"bytes,3,opt,name=handled_contracts,json=handledContracts,proto3" json:"handled_contracts,omitempty"`
	HandledTxs           *TransactionSet `protobuf:"bytes,4,opt,name=handled_txs,json=handledTxs,proto3" json:"handled_txs,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *HandledData) Reset()         { *m = HandledData{} }
func (m *HandledData) String() string { return proto.CompactTextString(m) }
func (*HandledData) ProtoMessage()    {}
func (*HandledData) Descriptor() ([]byte, []int) {
	return fileDescriptor_f750e0f7889345b5, []int{2}
}
func (m *HandledData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HandledData.Unmarshal(m, b)
}
func (m *HandledData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HandledData.Marshal(b, m, deterministic)
}
func (m *HandledData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HandledData.Merge(m, src)
}
func (m *HandledData) XXX_Size() int {
	return xxx_messageInfo_HandledData.Size(m)
}
func (m *HandledData) XXX_DiscardUnknown() {
	xxx_messageInfo_HandledData.DiscardUnknown(m)
}

var xxx_messageInfo_HandledData proto.InternalMessageInfo

func (m *HandledData) GetPrevRoundProductions() int32 {
	if m != nil {
		return m.PrevRoundProductions
	}
	return 0
}

func (m *HandledData) GetWinningTimes() uint64 {
	if m != nil {
		return m.WinningTimes
	}
	return 0
}

func (m *HandledData) GetHandledContracts() *ContractSet {
	if m != nil {
		return m.HandledContracts
	}
	return nil
}

func (m *HandledData) GetHandledTxs() *TransactionSet {
	if m != nil {
		return m.HandledTxs
	}
	return nil
}

type Voter struct {
	Address              []byte       `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	HandedData           *HandledData `protobuf:"bytes,2,opt,name=handed_data,json=handedData,proto3" json:"handed_data,omitempty"`
	Amount               []byte       `protobuf:"bytes,3,opt,name=amount,proto3" json:"amount,omitempty"`
	CreditIndex          []byte       `protobuf:"bytes,4,opt,name=credit_index,json=creditIndex,proto3" json:"credit_index,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *Voter) Reset()         { *m = Voter{} }
func (m *Voter) String() string { return proto.CompactTextString(m) }
func (*Voter) ProtoMessage()    {}
func (*Voter) Descriptor() ([]byte, []int) {
	return fileDescriptor_f750e0f7889345b5, []int{3}
}
func (m *Voter) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Voter.Unmarshal(m, b)
}
func (m *Voter) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Voter.Marshal(b, m, deterministic)
}
func (m *Voter) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Voter.Merge(m, src)
}
func (m *Voter) XXX_Size() int {
	return xxx_messageInfo_Voter.Size(m)
}
func (m *Voter) XXX_DiscardUnknown() {
	xxx_messageInfo_Voter.DiscardUnknown(m)
}

var xxx_messageInfo_Voter proto.InternalMessageInfo

func (m *Voter) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *Voter) GetHandedData() *HandledData {
	if m != nil {
		return m.HandedData
	}
	return nil
}

func (m *Voter) GetAmount() []byte {
	if m != nil {
		return m.Amount
	}
	return nil
}

func (m *Voter) GetCreditIndex() []byte {
	if m != nil {
		return m.CreditIndex
	}
	return nil
}

func init() {
	proto.RegisterType((*ContractSet)(nil), "corepb.ContractSet")
	proto.RegisterType((*TransactionSet)(nil), "corepb.TransactionSet")
	proto.RegisterType((*HandledData)(nil), "corepb.HandledData")
	proto.RegisterType((*Voter)(nil), "corepb.Voter")
}

func init() { proto.RegisterFile("index.proto", fileDescriptor_f750e0f7889345b5) }

var fileDescriptor_f750e0f7889345b5 = []byte{
	// 357 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x54, 0x92, 0x31, 0x4f, 0xc3, 0x30,
	0x10, 0x85, 0x15, 0x68, 0x8b, 0x38, 0x07, 0x54, 0x0c, 0xaa, 0xba, 0x20, 0x20, 0x2c, 0x0c, 0xa8,
	0x03, 0x54, 0x62, 0x45, 0x2a, 0x03, 0x6c, 0xc8, 0x44, 0xac, 0x96, 0x1b, 0x5f, 0x21, 0x52, 0x63,
	0x47, 0xb6, 0x0b, 0x59, 0xf9, 0x0b, 0xfc, 0x44, 0x7e, 0x09, 0x8a, 0x1d, 0x43, 0x3a, 0xfa, 0xf9,
	0xf3, 0xdd, 0x7b, 0x4f, 0x06, 0x52, 0x2a, 0x89, 0xcd, 0xac, 0x36, 0xda, 0x69, 0x3a, 0x2a, 0xb4,
	0xc1, 0x7a, 0x99, 0x7d, 0x25, 0x40, 0x16, 0x5a, 0x39, 0x23, 0x0a, 0xf7, 0x82, 0x8e, 0x9e, 0x01,
	0x51, 0xda, 0x54, 0x62, 0xcd, 0x0b, 0xad, 0xec, 0x34, 0x39, 0x4f, 0xae, 0x06, 0x0c, 0x82, 0xb4,
	0xd0, 0xca, 0xd2, 0x4b, 0x38, 0x70, 0x58, 0xd5, 0x6b, 0xe1, 0x30, 0x20, 0x3b, 0x1e, 0x49, 0xa3,
	0xe8, 0xa1, 0x6b, 0xa0, 0x5b, 0x10, 0x37, 0xb8, 0xb2, 0xd3, 0x5d, 0x4f, 0x8e, 0xfb, 0x24, 0xc3,
	0x95, 0xcd, 0x18, 0x1c, 0xe6, 0x46, 0x28, 0x2b, 0x0a, 0x57, 0x6a, 0xd5, 0xba, 0x38, 0x85, 0x6e,
	0x25, 0x77, 0x4d, 0x34, 0xb1, 0x1f, 0x94, 0xbc, 0xb1, 0xf4, 0x02, 0xd2, 0xa2, 0xf3, 0xec, 0x81,
	0x60, 0x81, 0x44, 0x2d, 0x6f, 0x6c, 0xf6, 0x93, 0x00, 0x79, 0x14, 0x4a, 0xae, 0x51, 0x3e, 0x08,
	0x27, 0xe8, 0x1c, 0x26, 0xb5, 0xc1, 0x0f, 0x6e, 0xf4, 0x46, 0x49, 0x5e, 0x1b, 0x2d, 0x37, 0x7e,
	0x5b, 0x98, 0x3e, 0x64, 0x27, 0xed, 0x2d, 0x6b, 0x2f, 0x9f, 0xff, 0xef, 0x68, 0x06, 0xe9, 0x67,
	0xa9, 0x54, 0xa9, 0xde, 0xf2, 0xb2, 0xc2, 0xbf, 0xac, 0x7d, 0x8d, 0xde, 0xc3, 0xd1, 0x7b, 0x58,
	0xc4, 0xa3, 0x81, 0x10, 0x95, 0xdc, 0x1c, 0xcf, 0x42, 0xcb, 0xb3, 0x5e, 0xc3, 0x6c, 0xdc, 0xd1,
	0x51, 0xb3, 0xf4, 0x0e, 0x48, 0x9c, 0xd0, 0xa6, 0x19, 0xf8, 0xb7, 0x93, 0xf8, 0x76, 0xbb, 0x1a,
	0x06, 0x1d, 0xda, 0x86, 0xfc, 0x4e, 0x60, 0xf8, 0xaa, 0x1d, 0x1a, 0x3a, 0x85, 0x3d, 0x21, 0xa5,
	0x41, 0x1b, 0xf2, 0xa4, 0x2c, 0x1e, 0xe9, 0x3c, 0x0c, 0x47, 0xc9, 0xa5, 0x70, 0xc2, 0x27, 0xe8,
	0x19, 0xeb, 0x55, 0x14, 0x26, 0x77, 0x75, 0x4d, 0x60, 0x24, 0x2a, 0xbd, 0x51, 0xce, 0x27, 0x49,
	0x59, 0x77, 0xf2, 0xcd, 0x1b, 0x94, 0xa5, 0xe3, 0xfe, 0x33, 0x79, 0xaf, 0x29, 0x23, 0x41, 0x7b,
	0x6a, 0xa5, 0xe5, 0xc8, 0x7f, 0xb0, 0xdb, 0xdf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0xa4, 0xa4,
	0xe0, 0x6f, 0x02, 0x00, 0x00,
}
