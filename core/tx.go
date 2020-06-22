// Copyright (C) 2018 go-cloudcard authors
//
// This file is part of the go-cloudcard library.
//
// the go-cloudcard library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// the go-cloudcard library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the go-cloudcard library.  If not, see <http://www.gnu.org/licenses/>.
//
package core

import (
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto/ed25519"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto/keystore"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gogo/protobuf/proto"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/sha3"
	"math/big"
	"regexp"
	"strings"
	"time"
)

const (
	PledgeTx         = "PledgeTx"
	TransferTx       = "TransferTx"
	ComplexTx        = "ComplexTx"
	ContractDeployTx = "ContractDeployTx"
	ContractInvokeTx = "ContractInvokeTx"
	ContractClosedTx = "ContractClosedTx"

	PriorityNormal = 0
	PriorityHigh   = 255

	nC = int64(1)
	uC = int64(100 * nC)
	mC = int64(100 * uC)
	cC = int64(100 * mC)
	C  = int64(100 * cC)

	UintPricePerByte  = 10 * uC
	ContractInvokeFee = 10 * mC

	Thousand = int64(1000)

	Decimals        = 8
	ZeroString      = "0"
	ZeroCUintString = "0.00000000"
	Minus           = "-"
	Dot             = "."
	Numerical       = "-[0-9]+(.[0-9]+)?|[0-9]+(.[0-9]+)?"
)

var (
	TxDataIsNilError          = errors.New("transaction data is nil")
	TxDataMsgIsNilError       = errors.New("transaction data msg is nil or length is 0")
	TransactionTypeNotSupport = errors.New("the transaction type is nonsupport")
	TransactionTypeMismatch   = errors.New("transaction type mismatch")
	IllegalAmountError        = errors.New("the amount must be greater than 0")
	IllegalAddressError       = errors.New("address is nil or length is not 37")
	ToAddressIsNilError       = errors.New("to address is nil")
	UnmarshalDataError        = errors.New("unmarshal data error")
	MarshalDataError          = errors.New("marshal data error")
	ComplexTxTypeError        = errors.New("complex transaction can not contain complex transaction")
	IllegalPriorityRangeError = errors.New("transaction priority out of rang")
	AmountNotEnoughError      = errors.New("amount not enough to create contract")
	TxFeeInvalidError         = errors.New("the transaction fee is not equal to the calculated transaction fee")

	ValueCanNotToBigIntError = errors.New("value string can not transfer to big int")
	ValueIsNotValid          = errors.New("the value must be greater than 0")
	IsNotNumericalValueError = errors.New("the value is not numerical value")
)

// Transaction
type Transaction struct {
	hash      byteutils.Hash
	from      *Address
	to        *Address
	value     *big.Int
	nonce     uint64
	chainId   uint32
	fee       *big.Int
	timestamp int64
	data      *corepb.Data
	priority  uint32
	sign      *corepb.Signature
}

type TransactionReceipt struct {
	Tx          *Transaction
	BlockHash   string
	BlockHeight uint64
	//tx status {1:SUCCESS、0：FAILED}
	Status uint32
	//tx error_message
	ErrorMessage string
}

// Transactions is an alias of Transaction array.
type Transactions []*Transaction

// NewTransaction
func NewTransaction(from, to *Address, amount *big.Int, nonce uint64, chainId, priority uint32, txType string, msg []byte) (*Transaction, error) {
	if priority > PriorityHigh {
		return nil, IllegalPriorityRangeError
	}
	switch txType {
	case PledgeTx:
		return NewPledgeTransaction(from, amount, nonce, chainId, priority, txType, msg)
	case TransferTx:
		return NewTransferTransaction(from, to, amount, nonce, chainId, priority, txType, msg)
	case ComplexTx:
		return NewComplexTransaction(from, to, amount, nonce, chainId, priority, txType, msg)
	case ContractDeployTx:
		return NewContractCreation(from, amount, nonce, chainId, priority, txType, msg)
	case ContractInvokeTx:
		return NewContractInvoke(from, to, nonce, chainId, priority, txType, msg)
	case ContractClosedTx:
		return NewContractClose(from, to, nonce, chainId, priority, txType, msg)
	default:
		logging.VLog().WithField(
			"tx.data.type", txType,
		).Error("Unsupported transaction types")
		return nil, TransactionTypeNotSupport
	}
}

// NewTransferTransaction
func NewTransferTransaction(from, to *Address, amount *big.Int, nonce uint64, chainId, priority uint32, txType string, msg []byte) (*Transaction, error) {
	if txType != TransferTx {
		return nil, TransactionTypeMismatch
	}
	if to == nil {
		return nil, ToAddressIsNilError
	}
	if amount == nil || amount.Cmp(big.NewInt(0)) <= 0 {
		return nil, IllegalAmountError
	}

	data, err := buildData(txType, msg)
	if err != nil {
		return nil, err
	}
	return newTransaction(from, to, amount, nonce, chainId, priority, data)
}

// NewContractCreation
func NewContractCreation(from *Address, amount *big.Int, nonce uint64, chainId, priority uint32, txType string, msg []byte) (*Transaction, error) {
	if ContractDeployTx != txType {
		return nil, TransactionTypeMismatch
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}

	if amount == nil || amount.Cmp(big.NewInt(0)) <= 0 {
		return nil, IllegalAmountError
	}

	data, err := buildData(txType, msg)
	if err != nil {
		return nil, err
	}
	tx, err := newTransaction(from, nil, amount, nonce, chainId, priority, data)
	if err != nil {
		return nil, err
	}
	//check amount > tx.fee+1000 * ContractInvokeFee
	referenceAmount := big.NewInt(Thousand)
	referenceAmount.Mul(referenceAmount, big.NewInt(ContractInvokeFee))
	referenceAmount.Add(referenceAmount, tx.fee)
	if amount.Cmp(referenceAmount) < 0 {
		logging.CLog().WithFields(logrus.Fields{
			"value":      amount.String(),
			"calc value": referenceAmount.String(),
		}).Debug(AmountNotEnoughError.Error())
		return nil, AmountNotEnoughError
	}
	return tx, nil
}

// NewContractInvoke
func NewContractInvoke(from, to *Address, nonce uint64, chainId, priority uint32, txType string, msg []byte) (*Transaction, error) {
	if ContractInvokeTx != txType {
		return nil, TransactionTypeMismatch
	}
	if to == nil {
		return nil, ToAddressIsNilError
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}
	data, err := buildData(txType, msg)
	if err != nil {
		return nil, err
	}
	return newTransaction(from, to, nil, nonce, chainId, priority, data)
}

// NewContractClose
func NewContractClose(from, to *Address, nonce uint64, chainId, priority uint32, txType string, msg []byte) (*Transaction, error) {
	if ContractClosedTx != txType {
		return nil, TransactionTypeMismatch
	}
	if to == nil {
		return nil, ToAddressIsNilError
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}
	data, err := buildData(txType, msg)
	if err != nil {
		return nil, err
	}
	return newTransaction(from, to, nil, nonce, chainId, priority, data)
}

// NewFileTransaction
func NewComplexTransaction(from, to *Address, amount *big.Int, nonce uint64, chainId, priority uint32, txType string, msg []byte) (*Transaction, error) {
	if ComplexTx != txType {
		return nil, TransactionTypeMismatch
	}
	if msg == nil || len(msg) == 0 {
		return nil, TxDataMsgIsNilError
	}
	complexData := new(corepb.ComplexData)
	if err := proto.Unmarshal(msg, complexData); err != nil {
		logging.VLog().Error("Failed to unmarshal data.")
		return nil, UnmarshalDataError
	}

	if complexData.Data == nil {
		return nil, TxDataIsNilError
	}

	if ComplexTx == complexData.Data.Type {
		return nil, ComplexTxTypeError
	}
	resultFiles := processDocumentTx(complexData)

	//not contain file tx
	if resultFiles == nil {
		resultBytes, err := proto.Marshal(complexData.Data)
		if err != nil {
			logging.VLog().Error("Failed to marshal complexData.Data")
			return nil, MarshalDataError
		}

		tx, err := NewTransaction(from, to, amount, nonce, chainId, priority, complexData.Data.Type, resultBytes)
		if err != nil {
			return nil, err
		}
		tx.data.Type = ComplexTx
		return tx, nil
	}

	//complexData.Flies = resultFiles
	resultBytes, err := proto.Marshal(complexData)
	if err != nil {
		logging.VLog().Error("Failed to marshal complexData")
		return nil, MarshalDataError
	}
	tx, err := NewTransaction(from, to, amount, nonce, chainId, priority, complexData.Data.Type, resultBytes)
	if err != nil {
		return nil, err
	}
	//recalculate the fee, including the file portion
	price := big.NewInt(UintPricePerByte)
	fileSize := len(msg) - len(complexData.Data.Msg)
	fileFee := price.Mul(price, big.NewInt(int64(fileSize)))
	tx.fee.Add(tx.fee, fileFee)
	//set tx type to ComplexTx
	tx.data.Type = ComplexTx

	return tx, nil
}

// NewPledgeTransaction
func NewPledgeTransaction(from *Address, amount *big.Int, nonce uint64, chainId, priority uint32, txType string, msg []byte) (*Transaction, error) {
	if PledgeTx != txType {
		return nil, TransactionTypeMismatch
	}
	if amount == nil || amount.Cmp(big.NewInt(0)) <= 0 {
		return nil, IllegalAmountError
	}
	data, err := buildData(txType, msg)
	if err != nil {
		return nil, err
	}
	return newTransaction(from, nil, amount, nonce, chainId, priority, data)
}

// newTransaction
func newTransaction(from, to *Address, amount *big.Int, nonce uint64, chainId, priority uint32, data *corepb.Data) (*Transaction, error) {
	tx := Transaction{
		from:      from,
		to:        to,
		value:     amount,
		nonce:     nonce,
		chainId:   chainId,
		data:      data,
		priority:  priority,
		timestamp: time.Now().UnixNano(),
	}

	if data.Type == ContractInvokeTx {
		tx.fee = big.NewInt(ContractInvokeFee)
	} else {
		tx.fee = tx.CalcFee()
	}

	txHash, err := tx.CalcHash()
	if err != nil {
		return nil, err
	}
	tx.hash = txHash

	return &tx, nil
}

func (tx *Transaction) Nonce() uint64        { return tx.nonce }
func (tx *Transaction) Hash() byteutils.Hash { return tx.hash }
func (tx *Transaction) Timestamp() int64     { return tx.timestamp }
func (tx *Transaction) Type() string         { return tx.data.Type }
func (tx *Transaction) Priority() uint32     { return tx.priority }
func (tx *Transaction) ChainId() uint32      { return tx.chainId }

// Sign
func (tx *Transaction) Sign(signature keystore.Signature) error {
	if signature == nil {
		return ErrNilArgument
	}
	sign, err := signature.Sign(tx.hash)
	if err != nil {
		return err
	}
	tx.sign = &corepb.Signature{
		Signer: sign.GetSigner(),
		Data:   sign.GetData(),
	}
	return nil
}

// SetSign
func (tx *Transaction) SetSign(signature *corepb.Signature) {
	tx.sign = signature
}

// TxFrom
func (tx *Transaction) From() *Address {
	if tx.from == nil {
		return nil
	}
	from := *tx.from
	return &from
}

// TxTo
func (tx *Transaction) To() *Address {
	if tx.to == nil {
		return nil
	}
	to := *tx.to
	return &to
}

// TxValue
func (tx *Transaction) GetValue() *big.Int {
	if tx == nil || tx.value == nil {
		return nil
	}
	value := *tx.value
	return &value
}

// TxValue
func (tx *Transaction) GetFee() *big.Int {
	if tx == nil || tx.fee == nil {
		return nil
	}
	value := *tx.fee
	return &value
}

// TxValue
func (tx *Transaction) GetData() *corepb.Data {
	if tx == nil || tx.data == nil {
		return nil
	}
	data := *tx.data
	return &data
}

// GetHexSignature
func (tx *Transaction) GetHexSignature() string {
	return byteutils.Hex(tx.sign.Data)
}

func (tx *Transaction) GetSign() *corepb.Signature {
	return tx.sign
}

// GetHexSignature
func (tx *Transaction) GetHexSignAndPubKey() (string, string) {
	return byteutils.Hex(tx.sign.Data), byteutils.Hex(tx.sign.Signer)
}

// CheckTx checks if the tx in world state.
func CheckTransaction(tx *Transaction, ws WorldState) (bool, error) {
	fromAcc, err := ws.GetOrCreateAccount(tx.from.address)
	if err != nil {
		return true, err
	}
	currentNonce := fromAcc.Nonce()
	if tx.nonce < currentNonce+1 {
		return false, ErrSmallTransactionNonce // nonce is too small
	} else if tx.nonce > currentNonce+1 {
		return true, ErrLargeTransactionNonce // nonce is too large
	}

	return false, nil
}

// execute transfer transaction
func executeTransferTransaction(tx *Transaction, block *Block, ws WorldState) (bool, error) {
	fromAcc, err := ws.GetOrCreateAccount(tx.from.address) // sender account
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get from account")
		return true, err
	}

	toAcc, err := ws.GetOrCreateAccount(tx.to.address) // receiver account
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get to account")
		return true, err
	}

	minerAcc, err := ws.GetOrCreateAccount(block.header.coinbase.address) // miner account
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get to miner account")
		return true, err
	}

	if fromAcc.Balance().Cmp(tx.fee) < 0 {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("not enough balance for fee")
		return false, ErrInsufficientBalance
	}

	balanceRequired := new(big.Int).Add(tx.fee, tx.value)
	if fromAcc.Balance().Cmp(balanceRequired) < 0 {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("insufficient balance")
		return false, ErrInsufficientBalance
	}

	var subErr, addErr, addMintFeeErr error

	subErr = fromAcc.SubBalance(balanceRequired) // sub (tx.value + tx.fee) from sender
	if subErr == nil {
		addErr = toAcc.AddBalance(tx.value) // add tx.value to receiver
		if addErr == nil {
			addMintFeeErr = minerAcc.AddBalance(tx.fee) // add tx's fee to miner
		}
	}

	if subErr != nil || addErr != nil || addMintFeeErr != nil {
		logging.VLog().WithFields(logrus.Fields{
			"subErr":        subErr,
			"addErr":        addErr,
			"addMintFeeErr": addMintFeeErr,
			"tx":            tx,
			"fromBalance":   fromAcc.Balance(),
			"toBalance":     toAcc.Balance(),
			"block":         block,
		}).Error("Failed to transfer value, unexpected error")
		return true, ErrInvalidTransfer
	}

	return false, nil
}

//
func executePledgeTransaction(tx *Transaction, block *Block, ws WorldState) (bool, error) {
	fromAcc, err := ws.GetOrCreateAccount(tx.from.address) // sender account
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get from account")
		return true, err
	}

	minerAcc, err := ws.GetOrCreateAccount(block.header.coinbase.address) // miner account
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to get to miner account")
		return true, err
	}

	if fromAcc.Balance().Cmp(tx.fee) < 0 {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("not enough balance for fee")
		return false, ErrInsufficientBalance
	}

	balanceRequired := new(big.Int).Add(tx.fee, tx.value)
	if fromAcc.Balance().Cmp(balanceRequired) < 0 {
		logging.VLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("insufficient balance")
		return false, ErrInsufficientBalance
	}

	var subErr, addPledgeErr, addMintFeeErr error
	subErr = fromAcc.SubBalance(balanceRequired) // sub balance
	if subErr == nil {
		addPledgeErr = fromAcc.AddPledgeFund(tx.value) // add pledge
		if addPledgeErr == nil {
			addMintFeeErr = minerAcc.AddBalance(tx.fee) // add tx's fee to miner
		}
	}

	if subErr != nil || addPledgeErr != nil || addMintFeeErr != nil {
		logging.VLog().WithFields(logrus.Fields{
			"subErr":        subErr,
			"addPledgeErr":  addPledgeErr,
			"addMintFeeErr": addMintFeeErr,
			"tx":            tx,
			"fromBalance":   fromAcc.Balance(),
			"block":         block,
		}).Error("Failed to transfer value, unexpected error")
		return true, ErrInvalidTransfer
	}

	return false, nil
}

// VerifyExecution verifies tx in block and returns result.
func VerifyExecution(tx *Transaction, block *Block, ws WorldState) (bool, error) {
	switch tx.Type() {
	case TransferTx:
		return executeTransferTransaction(tx, block, ws)
	case PledgeTx:
		return executePledgeTransaction(tx, block, ws)
	}

	return false, nil
}

// AcceptTx accepts a tx in world state.
func AcceptTransaction(tx *Transaction, ws WorldState) (bool, error) {
	// record tx
	pbTx, err := tx.ToProto()
	if err != nil {
		return true, err
	}
	txBytes, err := proto.Marshal(pbTx)
	if err != nil {
		return true, err
	}
	if err := ws.PutTx(tx.hash, txBytes); err != nil {
		return true, err
	}
	// incre nonce
	fromAcc, err := ws.GetOrCreateAccount(tx.from.address)
	if err != nil {
		return true, err
	}
	fromAcc.IncreaseNonce()
	// No error, won't giveback the tx
	return false, nil
}

// ToProto converts domain Tx to proto Tx
func (tx *Transaction) ToProto() (proto.Message, error) {
	protoTx := corepb.Transaction{
		Hash:      tx.hash,
		From:      tx.from.address,
		Nonce:     tx.nonce,
		ChainId:   tx.chainId,
		Fee:       tx.fee.Bytes(),
		Timestamp: tx.timestamp,
		Priority:  tx.priority,
		Sign:      tx.sign,
	}
	if tx.value != nil {
		protoTx.Value = tx.value.Bytes()
	}
	if tx.to != nil {
		protoTx.To = tx.to.address
	}
	if tx.data != nil {
		protoTx.Data = tx.data
	}

	return &protoTx, nil
}

// FromProto converts proto Tx to domain Tx
func (tx *Transaction) FromProto(msg proto.Message) error {
	if msg, ok := msg.(*corepb.Transaction); ok {
		if msg != nil {
			tx.hash = msg.Hash
			from, err := AddressParseFromBytes(msg.From)
			if err != nil {
				return ErrInvalidProtoToTransaction
			}
			tx.from = from
			if len(msg.To) > 0 {
				to, err := AddressParseFromBytes(msg.To)
				if err != nil {
					return ErrInvalidProtoToTransaction
				}
				tx.to = to
			}
			if len(msg.Value) > 0 {
				tx.value = new(big.Int).SetBytes(msg.Value)
			}
			tx.nonce = msg.Nonce
			tx.chainId = msg.ChainId
			tx.fee = new(big.Int).SetBytes(msg.Fee)
			tx.timestamp = msg.Timestamp
			tx.data = msg.Data
			tx.priority = msg.Priority
			tx.sign = msg.Sign
			return nil
		}
		return ErrInvalidProtoToTransaction
	}
	return ErrInvalidProtoToTransaction
}

// VerifyIntegrity return transaction verify result, including Hash and Signature.
func (tx *Transaction) VerifyIntegrity(chainId uint32) error {
	// check ChainID.
	if tx.chainId != chainId {
		return ErrInvalidChainID
	}
	calcFee := tx.CalcFee()
	if calcFee.Cmp(tx.fee) != 0 {
		logging.VLog().WithFields(logrus.Fields{
			"fee":     tx.fee.String(),
			"calcFee": calcFee.String(),
		}).Debug("Failed to verify tx's fee.")
		return TxFeeInvalidError
	}

	// check Hash.
	wantedHash, err := tx.CalcHash()
	if err != nil {
		return err
	}
	if wantedHash.Equals(tx.hash) == false {
		return ErrInvalidTransactionHash
	}

	// check Signature.
	return tx.verifySign()

}

// NcUnitToCUnitString
func NcUnitToCUnitString(value *big.Int) string {
	if value == nil || value.String() == ZeroString {
		return ZeroCUintString
	}
	valueStr := value.String()
	//value length more than 8
	if len(valueStr) > 8 {
		dotPos := len(valueStr) - Decimals
		integerStr := valueStr[:dotPos]
		decimals := valueStr[dotPos:]
		valueStr = integerStr + Dot + decimals
		return valueStr
	}

	//value length less than 8, add prefix zero string
	if len(valueStr) < Decimals {
		count := Decimals - len(valueStr)
		valueStr = addPrefixZero(valueStr, uint8(count))
	}
	//value length equals 8 or less than 8, add zero and dot string
	//for example 0.12345678  or   0.00123456
	valueStr = ZeroString + Dot + valueStr
	return valueStr
}

// CUintStringToNcUintBigInt
func CUintStringToNcUintBigInt(valueStr string) (*big.Int, error) {
	value := valueStr
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, Minus) {
		logging.CLog().WithFields(logrus.Fields{
			"value": valueStr,
		}).Debug("value is minus number")
		return nil, ValueIsNotValid
	}
	if strings.HasPrefix(value, Dot) {
		logging.CLog().WithFields(logrus.Fields{
			"value": valueStr,
		}).Debug("value string start whit dot")
		return nil, ValueCanNotToBigIntError
	}

	reg := regexp.MustCompile(Numerical)
	isNumber := reg.MatchString(value)
	if !isNumber {
		return nil, IsNotNumericalValueError
	}

	split := strings.Split(value, Dot)
	var amount *big.Int
	result := true
	if len(split) == 1 {
		amount, result = new(big.Int).SetString(value, 0)
		if !result {
			logging.CLog().WithFields(logrus.Fields{
				"value:": valueStr,
				"error":  ValueCanNotToBigIntError,
			}).Debug("value can not to big int")
			return nil, ValueCanNotToBigIntError
		}
		amount.Mul(amount, big.NewInt(C))
		return amount, nil
	}

	integer := split[0]
	decimal := split[1]
	if len(decimal) < Decimals {
		j := Decimals - len(decimal)
		for i := 0; i < j; i++ {
			decimal += ZeroString
		}
	}

	if len(decimal) > Decimals {
		decimal = decimal[:Decimals]
	}

	value = integer + decimal
	value = trimPrefixZero(value)

	amount, result = new(big.Int).SetString(value, 0)

	if !result {
		logging.CLog().WithFields(logrus.Fields{
			"value:": valueStr,
			"error":  ValueCanNotToBigIntError,
		}).Debug("value can not to big int")
		return nil, ValueCanNotToBigIntError
	}

	return amount, nil
}

// verifySign
func (tx *Transaction) verifySign() error {
	signer, err := NewAddressFromPublicKey(tx.sign.Signer)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"tx.sign.Signer": hex.EncodeToString(tx.sign.Signer),
		}).Debug("Failed to verify tx's sign.")
		return ErrInvalidPublicKey
	}
	if !tx.from.Equals(signer) {
		logging.VLog().WithFields(logrus.Fields{
			"signer":  signer.String(),
			"tx.from": tx.from,
		}).Debug("Failed to verify tx's sign.")
		return ErrInvalidTransactionSigner
	}

	sign := new(ed25519.Signature)
	verify, err := sign.Verify(tx.hash, tx.sign)
	if !verify {
		logging.VLog().WithFields(logrus.Fields{
			"txHash": tx.hash,
			"sign":   byteutils.Hex(tx.sign.Data),
			"pubKey": byteutils.Hex(tx.sign.Signer),
			"err":    err,
		}).Info("Failed to check transaction's signature.")
		return ErrInvalidTransactionSign
	}

	return nil
}

// HashTransaction hash the transaction.
func (tx *Transaction) CalcHash() (byteutils.Hash, error) {
	hasher := sha3.New256()

	data, err := proto.Marshal(tx.data)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error": err,
		}).Error("proto.Marshal(tx.data) error")
		return nil, err
	}

	hasher.Write(tx.from.address)

	if tx.to != nil {
		hasher.Write(tx.to.address)
	}

	if tx.value != nil {
		hasher.Write(tx.value.Bytes())
	}
	hasher.Write(byteutils.FromUint64(tx.nonce))
	hasher.Write(byteutils.FromUint32(tx.chainId))
	hasher.Write(tx.fee.Bytes())
	hasher.Write(byteutils.FromInt64(tx.timestamp))
	hasher.Write(data)
	hasher.Write(byteutils.FromUint32(tx.priority))

	return hasher.Sum(nil), nil
}

// calc tx fee
func (tx *Transaction) CalcFee() *big.Int {
	txByteSize := len(tx.data.Msg)
	if tx.from != nil {
		txByteSize += len(tx.from.address)
	}
	if tx.to != nil {
		txByteSize += len(tx.to.address)
	}
	if tx.value != nil {
		txByteSize += len(tx.value.Bytes())
	}
	//nonce、chainId、timestamp、priority numbers of bytes
	txByteSize = txByteSize + len(byteutils.FromUint64(tx.nonce)) + len(byteutils.FromUint32(tx.chainId))
	txByteSize = txByteSize + len(byteutils.FromUint32(tx.priority)) + len(byteutils.FromInt64(tx.timestamp))
	fee := big.NewInt(1).Mul(big.NewInt(UintPricePerByte), big.NewInt(int64(txByteSize)))
	return fee
}

// baseCheckTx
func (tx *Transaction) baseCheckTx() error {
	if tx.from == nil || tx.from.address == nil || len(tx.from.address) != 37 {
		return IllegalAddressError
	}
	if tx.to != nil {
		if tx.to.address == nil || len(tx.to.address) != 37 {
			return IllegalAddressError
		}
	}

	if tx.value != nil {
		if cmp := tx.value.Cmp(big.NewInt(0)); cmp <= 0 {
			return IllegalAmountError
		}
	}
	return nil
}

func (tx *Transaction) String() string {
	return fmt.Sprintf(`{"chainID":%d, "hash":"%s", "from":"%s", "to":"%s", "nonce":%d, "value":"%s", "timestamp":%d, "data": "%s", "type":"%s"}`,
		tx.chainId,
		tx.hash.String(),
		tx.from.String(),
		tx.to.String(),
		tx.nonce,
		tx.value.String(),
		tx.timestamp,
		tx.data.String(),
		tx.Type(),
	)
}

// buildData
func buildData(txType string, msg []byte) (*corepb.Data, error) {
	data := new(corepb.Data)
	data.Type = txType
	data.Msg = msg
	return data, nil
}

// processDocumentTx
func processDocumentTx(complexData *corepb.ComplexData) []*corepb.File {
	files := complexData.Flies
	if files == nil || len(files) < 1 {
		logging.VLog().Debug("the complex tx not contain file tx")
		return nil
	}

	for _, file := range files {
		storageState := new(corepb.StorageState)
		storageState.Result, _ = byteutils.FromHex("abc123")
		storageState.Mode = "test"
		file.State = storageState
		file.Size = uint64(len(file.Content))
		file.Content = nil
	}
	return files
}

// handle string start with 0
func trimPrefixZero(str string) string {
	startZero := strings.HasPrefix(str, ZeroString)
	if startZero {
		bytes := []byte(str)
		zeroCount := 0
		for i := 0; i < len(str); i++ {
			if string(bytes[i]) != ZeroString {
				break
			}
			zeroCount++
		}
		if zeroCount != len(str) {
			str = str[zeroCount:]
		}
	}
	return str
}

// addPrefixZero
func addPrefixZero(valueStr string, count uint8) string {
	for i := uint8(0); i < count; i++ {
		valueStr = ZeroString + valueStr
	}
	return valueStr
}

func CheckTxType(txType string) error {
	switch txType {
	case PledgeTx, TransferTx, ComplexTx, ContractInvokeTx, ContractDeployTx, ContractClosedTx:
		return nil
	default:
		return TransactionTypeNotSupport
	}
}
