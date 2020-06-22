// Code generated by protoc-gen-go. DO NOT EDIT.
// source: account.proto

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

type ContractAuthority struct {
	Address              []byte   `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Method               string   `protobuf:"bytes,2,opt,name=method,proto3" json:"method,omitempty"`
	AccessType           string   `protobuf:"bytes,3,opt,name=access_type,json=accessType,proto3" json:"access_type,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ContractAuthority) Reset()         { *m = ContractAuthority{} }
func (m *ContractAuthority) String() string { return proto.CompactTextString(m) }
func (*ContractAuthority) ProtoMessage()    {}
func (*ContractAuthority) Descriptor() ([]byte, []int) {
	return fileDescriptor_8e28828dcb8d24f0, []int{0}
}

func (m *ContractAuthority) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ContractAuthority.Unmarshal(m, b)
}
func (m *ContractAuthority) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ContractAuthority.Marshal(b, m, deterministic)
}
func (m *ContractAuthority) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ContractAuthority.Merge(m, src)
}
func (m *ContractAuthority) XXX_Size() int {
	return xxx_messageInfo_ContractAuthority.Size(m)
}
func (m *ContractAuthority) XXX_DiscardUnknown() {
	xxx_messageInfo_ContractAuthority.DiscardUnknown(m)
}

var xxx_messageInfo_ContractAuthority proto.InternalMessageInfo

func (m *ContractAuthority) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *ContractAuthority) GetMethod() string {
	if m != nil {
		return m.Method
	}
	return ""
}

func (m *ContractAuthority) GetAccessType() string {
	if m != nil {
		return m.AccessType
	}
	return ""
}

type Permission struct {
	AuthCategory         string   `protobuf:"bytes,1,opt,name=auth_category,json=authCategory,proto3" json:"auth_category,omitempty"`
	AuthMessage          [][]byte `protobuf:"bytes,2,rep,name=auth_message,json=authMessage,proto3" json:"auth_message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Permission) Reset()         { *m = Permission{} }
func (m *Permission) String() string { return proto.CompactTextString(m) }
func (*Permission) ProtoMessage()    {}
func (*Permission) Descriptor() ([]byte, []int) {
	return fileDescriptor_8e28828dcb8d24f0, []int{1}
}

func (m *Permission) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Permission.Unmarshal(m, b)
}
func (m *Permission) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Permission.Marshal(b, m, deterministic)
}
func (m *Permission) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Permission.Merge(m, src)
}
func (m *Permission) XXX_Size() int {
	return xxx_messageInfo_Permission.Size(m)
}
func (m *Permission) XXX_DiscardUnknown() {
	xxx_messageInfo_Permission.DiscardUnknown(m)
}

var xxx_messageInfo_Permission proto.InternalMessageInfo

func (m *Permission) GetAuthCategory() string {
	if m != nil {
		return m.AuthCategory
	}
	return ""
}

func (m *Permission) GetAuthMessage() [][]byte {
	if m != nil {
		return m.AuthMessage
	}
	return nil
}

type Contract struct {
	Address              []byte   `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Methods              []string `protobuf:"bytes,2,rep,name=methods,proto3" json:"methods,omitempty"`
	Version              string   `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Contract) Reset()         { *m = Contract{} }
func (m *Contract) String() string { return proto.CompactTextString(m) }
func (*Contract) ProtoMessage()    {}
func (*Contract) Descriptor() ([]byte, []int) {
	return fileDescriptor_8e28828dcb8d24f0, []int{2}
}

func (m *Contract) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Contract.Unmarshal(m, b)
}
func (m *Contract) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Contract.Marshal(b, m, deterministic)
}
func (m *Contract) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Contract.Merge(m, src)
}
func (m *Contract) XXX_Size() int {
	return xxx_messageInfo_Contract.Size(m)
}
func (m *Contract) XXX_DiscardUnknown() {
	xxx_messageInfo_Contract.DiscardUnknown(m)
}

var xxx_messageInfo_Contract proto.InternalMessageInfo

func (m *Contract) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *Contract) GetMethods() []string {
	if m != nil {
		return m.Methods
	}
	return nil
}

func (m *Contract) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

type Account struct {
	Address              []byte        `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Balance              []byte        `protobuf:"bytes,2,opt,name=balance,proto3" json:"balance,omitempty"`
	FrozenFund           []byte        `protobuf:"bytes,3,opt,name=frozen_fund,json=frozenFund,proto3" json:"frozen_fund,omitempty"`
	PledgeFund           []byte        `protobuf:"bytes,4,opt,name=pledge_fund,json=pledgeFund,proto3" json:"pledge_fund,omitempty"`
	Nonce                uint64        `protobuf:"varint,5,opt,name=nonce,proto3" json:"nonce,omitempty"`
	DoEvils              uint32        `protobuf:"varint,6,opt,name=do_evils,json=doEvils,proto3" json:"do_evils,omitempty"`
	VarsHash             []byte        `protobuf:"bytes,7,opt,name=vars_hash,json=varsHash,proto3" json:"vars_hash,omitempty"`
	Products             uint32        `protobuf:"varint,8,opt,name=products,proto3" json:"products,omitempty"`
	CreditIndex          []byte        `protobuf:"bytes,9,opt,name=credit_index,json=creditIndex,proto3" json:"credit_index,omitempty"`
	Permissions          []*Permission `protobuf:"bytes,10,rep,name=permissions,proto3" json:"permissions,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *Account) Reset()         { *m = Account{} }
func (m *Account) String() string { return proto.CompactTextString(m) }
func (*Account) ProtoMessage()    {}
func (*Account) Descriptor() ([]byte, []int) {
	return fileDescriptor_8e28828dcb8d24f0, []int{3}
}

func (m *Account) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Account.Unmarshal(m, b)
}
func (m *Account) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Account.Marshal(b, m, deterministic)
}
func (m *Account) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Account.Merge(m, src)
}
func (m *Account) XXX_Size() int {
	return xxx_messageInfo_Account.Size(m)
}
func (m *Account) XXX_DiscardUnknown() {
	xxx_messageInfo_Account.DiscardUnknown(m)
}

var xxx_messageInfo_Account proto.InternalMessageInfo

func (m *Account) GetAddress() []byte {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *Account) GetBalance() []byte {
	if m != nil {
		return m.Balance
	}
	return nil
}

func (m *Account) GetFrozenFund() []byte {
	if m != nil {
		return m.FrozenFund
	}
	return nil
}

func (m *Account) GetPledgeFund() []byte {
	if m != nil {
		return m.PledgeFund
	}
	return nil
}

func (m *Account) GetNonce() uint64 {
	if m != nil {
		return m.Nonce
	}
	return 0
}

func (m *Account) GetDoEvils() uint32 {
	if m != nil {
		return m.DoEvils
	}
	return 0
}

func (m *Account) GetVarsHash() []byte {
	if m != nil {
		return m.VarsHash
	}
	return nil
}

func (m *Account) GetProducts() uint32 {
	if m != nil {
		return m.Products
	}
	return 0
}

func (m *Account) GetCreditIndex() []byte {
	if m != nil {
		return m.CreditIndex
	}
	return nil
}

func (m *Account) GetPermissions() []*Permission {
	if m != nil {
		return m.Permissions
	}
	return nil
}

func init() {
	proto.RegisterType((*ContractAuthority)(nil), "corepb.ContractAuthority")
	proto.RegisterType((*Permission)(nil), "corepb.Permission")
	proto.RegisterType((*Contract)(nil), "corepb.Contract")
	proto.RegisterType((*Account)(nil), "corepb.Account")
}

func init() { proto.RegisterFile("account.proto", fileDescriptor_8e28828dcb8d24f0) }

var fileDescriptor_8e28828dcb8d24f0 = []byte{
	// 385 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0xcd, 0x8e, 0xd3, 0x30,
	0x14, 0x85, 0x95, 0x76, 0x26, 0x3f, 0x37, 0xe9, 0x02, 0x0b, 0x21, 0x03, 0x0b, 0x42, 0xd8, 0x64,
	0xd5, 0x05, 0xf0, 0x02, 0xa3, 0x11, 0x08, 0x16, 0x48, 0xc8, 0x9a, 0x05, 0xbb, 0xc8, 0xb5, 0x6f,
	0x9b, 0x48, 0xad, 0x1d, 0xd9, 0x4e, 0x45, 0x78, 0x3c, 0x9e, 0x0c, 0xd9, 0x6e, 0xca, 0xac, 0xba,
	0x3c, 0x9f, 0xaf, 0x8f, 0x8f, 0x8e, 0x2f, 0x6c, 0xb8, 0x10, 0x7a, 0x52, 0x6e, 0x3b, 0x1a, 0xed,
	0x34, 0x49, 0x85, 0x36, 0x38, 0xee, 0x9a, 0x3d, 0xbc, 0x78, 0xd4, 0xca, 0x19, 0x2e, 0xdc, 0xc3,
	0xe4, 0x7a, 0x6d, 0x06, 0x37, 0x13, 0x0a, 0x19, 0x97, 0xd2, 0xa0, 0xb5, 0x34, 0xa9, 0x93, 0xb6,
	0x62, 0x8b, 0x24, 0xaf, 0x20, 0x3d, 0xa1, 0xeb, 0xb5, 0xa4, 0xab, 0x3a, 0x69, 0x0b, 0x76, 0x51,
	0xe4, 0x1d, 0x94, 0x5c, 0x08, 0xb4, 0xb6, 0x73, 0xf3, 0x88, 0x74, 0x1d, 0x0e, 0x21, 0xa2, 0xa7,
	0x79, 0xc4, 0xe6, 0x09, 0xe0, 0x27, 0x9a, 0xd3, 0x60, 0xed, 0xa0, 0x15, 0xf9, 0x00, 0x1b, 0x3e,
	0xb9, 0xbe, 0x13, 0xdc, 0xe1, 0x41, 0x9b, 0x39, 0x3c, 0x53, 0xb0, 0xca, 0xc3, 0xc7, 0x0b, 0x23,
	0xef, 0x21, 0xe8, 0xee, 0x84, 0xd6, 0xf2, 0x03, 0xd2, 0x55, 0xbd, 0x6e, 0x2b, 0x56, 0x7a, 0xf6,
	0x23, 0xa2, 0xe6, 0x17, 0xe4, 0x4b, 0xfa, 0x1b, 0xa1, 0x29, 0x64, 0x31, 0xa6, 0x0d, 0x1e, 0x05,
	0x5b, 0xa4, 0x3f, 0x39, 0xa3, 0xf1, 0x91, 0x2e, 0x91, 0x17, 0xd9, 0xfc, 0x5d, 0x41, 0xf6, 0x10,
	0x1b, 0xbb, 0xed, 0xbc, 0xe3, 0x47, 0xae, 0x04, 0x86, 0x3e, 0x2a, 0xb6, 0x48, 0x5f, 0xc8, 0xde,
	0xe8, 0x3f, 0xa8, 0xba, 0xfd, 0xa4, 0x64, 0x70, 0xaf, 0x18, 0x44, 0xf4, 0x75, 0x52, 0xa1, 0xb1,
	0xf1, 0x88, 0xf2, 0x80, 0x71, 0xe0, 0x2e, 0x0e, 0x44, 0x14, 0x06, 0x5e, 0xc2, 0xbd, 0xd2, 0xde,
	0xf9, 0xbe, 0x4e, 0xda, 0x3b, 0x16, 0x05, 0x79, 0x0d, 0xb9, 0xd4, 0x1d, 0x9e, 0x87, 0xa3, 0xa5,
	0x69, 0x9d, 0xb4, 0x1b, 0x96, 0x49, 0xfd, 0xc5, 0x4b, 0xf2, 0x16, 0x8a, 0x33, 0x37, 0xb6, 0xeb,
	0xb9, 0xed, 0x69, 0x16, 0xfc, 0x72, 0x0f, 0xbe, 0x71, 0xdb, 0x93, 0x37, 0x90, 0x8f, 0x46, 0xcb,
	0x49, 0x38, 0x4b, 0xf3, 0x70, 0xef, 0xaa, 0x7d, 0xd1, 0xc2, 0xa0, 0x1c, 0x5c, 0x37, 0x28, 0x89,
	0xbf, 0x69, 0x11, 0xee, 0x96, 0x91, 0x7d, 0xf7, 0x88, 0x7c, 0x86, 0x72, 0xbc, 0x7e, 0x9f, 0xa5,
	0x50, 0xaf, 0xdb, 0xf2, 0x23, 0xd9, 0xc6, 0x25, 0xda, 0xfe, 0xff, 0x59, 0xf6, 0x7c, 0x6c, 0x97,
	0x86, 0x5d, 0xfb, 0xf4, 0x2f, 0x00, 0x00, 0xff, 0xff, 0x00, 0x11, 0x70, 0xa7, 0x7c, 0x02, 0x00,
	0x00,
}