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

package rpc

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/account"
	"cloudcard.pro/cloudcardio/go-cloudcard/consensus/psec"
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto"
	rpcpb "cloudcard.pro/cloudcardio/go-cloudcard/rpc/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	CoinbaseAddressIsNilError          = errors.New("the coinbase address is nil")
	PassphraseLengthIsZeroError        = errors.New("passphrase length is 0")
	MiningProcessingError              = errors.New("mining is in progress, please stop mining before starting")
	HasBeenStoppedError                = errors.New("the mining has been stopped, please restart")
	MessageLengthIsZeroError           = errors.New("message length must greater than 0")
	SignatureLengthIsZeroError         = errors.New("signature length must greater than 0")
	NotHexStringError                  = errors.New("not hex string")
	LogLevelLengthIsZeroError          = errors.New("the log level cannot be empty")
	LogAgeIsZeroError                  = errors.New("log age must be greater than 0")
	RotationTimeIsZeroError            = errors.New("rotation time must be greater than 0")
	LogPathIsEmptyError                = errors.New("the log path cannot be empty")
	BalanceNotEnoughError              = errors.New("balance not enough")
	TxPoolIsNilError                   = errors.New("tx poll is nil")
	DataIsNotHexStringError            = errors.New("data must be a hex string")
	PrivateKeyIsBlankError             = errors.New("private key is blank")
	PrivateKeyIsNotHexStrError         = errors.New("private key must be hex string")
	RotationTimeGreaterThanMaxAgeError = errors.New("rotation time must be less than max age")
	TxNonceLessThanAccountNonceError   = errors.New("transaction nonce must be greater than account nonce")
)

// AdminService implements the RPC admin service interface.
type AdminService struct {
	server  GRPCServer
	cloudcard    core.cloudcard
	log     *logrus.Logger
	logConf *logging.LogConfig
	zn      sync.Mutex //zero nonce send lock
}

func (s *AdminService) StartMining(ctx context.Context, req *rpcpb.PassphraseRequest) (*rpcpb.BoolResponse, error) {
	if len(req.Passphrase) == 0 {
		return &rpcpb.BoolResponse{Result: false}, PassphraseLengthIsZeroError
	}
	psecTemp := s.cloudcard.Consensus().(*psec.Psec)
	if psecTemp.IsEnable() {
		logging.CLog().Debug("mining is in progress ......")
		return &rpcpb.BoolResponse{Result: false}, MiningProcessingError
	}

	address := psecTemp.Coinbase()
	if address == nil {
		logging.CLog().Debug(CoinbaseAddressIsNilError.Error())
		return &rpcpb.BoolResponse{Result: false}, CoinbaseAddressIsNilError
	}
	s.zn.Lock()
	defer s.zn.Unlock()
	err := s.cloudcard.AccountManager().UnLock(address, []byte(req.Passphrase), time.Duration(psec.MaxMiningDuration*int64(time.Second)))
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"coinbaseAddress": address.String(),
			"passphrase":      req.Passphrase,
			"error":           err,
		}).Debug("unlock error")
		return &rpcpb.BoolResponse{Result: false}, err
	}
	psecTemp.StartMining()
	logging.CLog().Debug("start mining ......")
	return &rpcpb.BoolResponse{Result: true}, nil
}

func (s *AdminService) StopMining(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.BoolResponse, error) {
	psecTemp := s.cloudcard.Consensus().(*psec.Psec)
	if !psecTemp.IsEnable() {
		logging.CLog().Debug("has been stopped")
		return &rpcpb.BoolResponse{Result: false}, HasBeenStoppedError
	}
	address := psecTemp.Coinbase()
	if address == nil {
		logging.CLog().Debug(CoinbaseAddressIsNilError.Error())
		return &rpcpb.BoolResponse{Result: false}, CoinbaseAddressIsNilError
	}

	s.zn.Lock()
	defer s.zn.Unlock()
	psecTemp.Stop()
	err := s.cloudcard.AccountManager().Lock(address)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"coinbaseAddress": address.String(),
			"error":           err,
		}).Debug("lock error")
		return &rpcpb.BoolResponse{Result: false}, err
	}
	logging.CLog().Debug("stop mining ......")
	return &rpcpb.BoolResponse{Result: true}, nil
}

// Accounts is the RPC API handler.
func (s *AdminService) Accounts(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.AccountsResponse, error) {

	accs := s.cloudcard.AccountManager().GetAllAddress()

	resp := new(rpcpb.AccountsResponse)
	addrs := make([]string, len(accs))
	for index, addr := range accs {
		addrs[index] = addr.String()
	}
	resp.Addresses = addrs
	return resp, nil
}

// NewAccount generate a new address with passphrase
func (s *AdminService) NewAccount(ctx context.Context, req *rpcpb.PassphraseRequest) (*rpcpb.NewAccountResponse, error) {
	if len(req.Passphrase) == 0 {
		return nil, PassphraseLengthIsZeroError
	}
	addr, memo, err := s.cloudcard.AccountManager().NewAccount([]byte(req.Passphrase))
	if err != nil {
		return nil, err
	}
	return &rpcpb.NewAccountResponse{Address: addr.String(), Memo: memo}, nil
}

// NewAccount create a new account with passphrase
func (s *AdminService) UpdateAccount(ctx context.Context, req *rpcpb.UpdateAccountRequest) (*rpcpb.BoolResponse, error) {
	oldPassphrase := req.OldPassphrase
	newPassphrase := req.NewPassphrase
	if len(oldPassphrase) == 0 || len(newPassphrase) == 0 {
		return &rpcpb.BoolResponse{Result: false}, PassphraseLengthIsZeroError
	}
	addr, err := s.cloudcard.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		metricsUnlockFailed.Mark(1)
		return &rpcpb.BoolResponse{Result: false}, err
	}
	err = s.cloudcard.AccountManager().UpdateAccount(addr, []byte(oldPassphrase), []byte(newPassphrase))
	return &rpcpb.BoolResponse{Result: true}, err
}

// NewAccount create a new account with passphrase
func (s *AdminService) ImportAccount(ctx context.Context, req *rpcpb.PrivKeyAndPassphrase) (*rpcpb.Address, error) {
	if len(req.PriKey) == 0 {
		return nil, PrivateKeyIsBlankError
	}

	if len(req.Passphrase) == 0 {
		return nil, PassphraseLengthIsZeroError
	}
	privBytes, err := byteutils.FromHex(req.PriKey)
	if err != nil {
		return nil, PrivateKeyIsNotHexStrError
	}

	address, err := s.cloudcard.AccountManager().ImportAccount(privBytes, []byte(req.Passphrase))
	if err != nil {
		return nil, err
	}
	return &rpcpb.Address{Address: address.String()}, err
}

// UnlockAccount unlock address with the passphrase
func (s *AdminService) UnlockAccount(ctx context.Context, req *rpcpb.UnlockAccountRequest) (*rpcpb.BoolResponse, error) {
	if len(req.Passphrase) == 0 {
		return nil, PassphraseLengthIsZeroError
	}
	addr, err := s.cloudcard.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		metricsUnlockFailed.Mark(1)
		return nil, err
	}

	duration := time.Duration(req.Duration * uint64(time.Second))
	err = s.cloudcard.AccountManager().UnLock(addr, []byte(req.Passphrase), duration)
	if err != nil {
		metricsUnlockFailed.Mark(1)
		return nil, err
	}

	metricsUnlockSuccess.Mark(1)
	return &rpcpb.BoolResponse{Result: true}, nil
}

// LockAccount lock address
func (s *AdminService) LockAccount(ctx context.Context, req *rpcpb.LockAccountRequest) (*rpcpb.BoolResponse, error) {

	addr, err := s.cloudcard.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		return nil, err
	}

	err = s.cloudcard.AccountManager().Lock(addr)
	if err != nil {
		return nil, err
	}

	return &rpcpb.BoolResponse{Result: true}, nil
}

// SendTransaction is the RPC API handler.
func (s *AdminService) SendTransaction(ctx context.Context, req *rpcpb.TransactionRequest) (*rpcpb.TransactionHash, error) {
	tx, err := s.createTx(req)
	if err != nil {
		return nil, err
	}

	err = s.cloudcard.AccountManager().SignTx(tx.From(), tx)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"txHash": tx.Hash().String(),
			"error":  err.Error(),
		}).Debug("sign error")
		return nil, err
	}

	err = s.cloudcard.BlockChain().TxPool().AddAndBroadcast(tx)
	if err != nil {
		return nil, err
	}
	logging.CLog().WithFields(logrus.Fields{
		"txHash":  tx.Hash().String(),
		"txNonce": tx.Nonce(),
	}).Debug("send transaction success")

	return &rpcpb.TransactionHash{Hash: tx.Hash().String()}, nil
}

// SignHash is the RPC API handler.
func (s *AdminService) Sign(ctx context.Context, req *rpcpb.SignHashRequest) (*rpcpb.SignHashResponse, error) {

	addr, err := s.cloudcard.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		return nil, err
	}
	hash := req.Message
	if len(hash) == 0 {
		return nil, MessageLengthIsZeroError
	}
	hashBytes, err := byteutils.FromHex(hash)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"message": hash,
			"error":   err,
		}).Debug("the hash must be hex string")
		return nil, NotHexStringError
	}

	data, err := s.cloudcard.AccountManager().Sign(addr, hashBytes)
	if err != nil {
		return nil, err
	}
	sign := byteutils.Hex(data)

	return &rpcpb.SignHashResponse{Data: sign}, nil
}

// Sign sign msg
func (s *AdminService) VerifyMessage(ctx context.Context, req *rpcpb.VerifyMessageRequest) (*rpcpb.BoolResponse, error) {
	if len(req.Signature) == 0 {
		return &rpcpb.BoolResponse{Result: false}, SignatureLengthIsZeroError
	}

	if len(req.Message) == 0 {
		return &rpcpb.BoolResponse{Result: false}, MessageLengthIsZeroError
	}
	addr, err := s.cloudcard.AccountManager().AddressIsValid(req.Address)
	if err != nil {
		return nil, err
	}

	sign, err := byteutils.FromHex(req.Signature)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"sign":  req.Signature,
			"error": err,
		}).Debug("the sign must be hex string")
		return &rpcpb.BoolResponse{Result: false}, NotHexStringError
	}

	msg, err := byteutils.FromHex(req.Message)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"message": req.Message,
			"error":   err,
		}).Debug("the message must be hex string")
		return &rpcpb.BoolResponse{Result: false}, NotHexStringError
	}

	result, err := s.cloudcard.AccountManager().Verify(addr, msg, sign)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"sign":    req.Signature,
			"message": req.Message,
			"result":  result,
			"error":   err,
		}).Debug("verify signature error")
	}
	return &rpcpb.BoolResponse{Result: result}, err
}

//stop the server
func (s *AdminService) Stop(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.BoolResponse, error) {
	//Asynchronous close, first response to client request
	go func() {
		s.cloudcard.Stop()
	}()
	return &rpcpb.BoolResponse{Result: true}, nil
}

// SignTransactionWithPassphrase is the RPC API handler.
func (s *AdminService) SignTransactionWithPassphrase(ctx context.Context, req *rpcpb.SignTransactionPassphraseRequest) (*rpcpb.SignTransactionPassphraseResponse, error) {

	return nil, nil
}

// SendTransactionWithPassphrase is the RPC API handler.
func (s *AdminService) SendTransactionWithPassphrase(ctx context.Context, req *rpcpb.SendTransactionPassphraseRequest) (*rpcpb.TransactionHash, error) {

	return nil, nil
}

// StartPprof is the RPC API handler.
func (s *AdminService) StartPprof(ctx context.Context, req *rpcpb.PprofRequest) (*rpcpb.PprofResponse, error) {

	return nil, nil
}

//return Logging Info
func (s *AdminService) Logging(ctx context.Context, req *rpcpb.LoggingInfo) (*rpcpb.LoggingInfo, error) {
	path := s.logConf.LogFile
	if len(req.LogPath) == 0 {
		if !filepath.IsAbs(path) {
			path, _ = filepath.Abs(path)
		}
	}
	if len(req.LogPath) == 0 && len(req.LogLevel) == 0 && req.LogAge == 0 && req.RotationTime == 0 {
		return &rpcpb.LoggingInfo{
			LogLevel:     s.logConf.LogLevel,
			LogPath:      path,
			LogAge:       s.logConf.LogAge,
			RotationTime: uint32(s.logConf.LogRotationTime),
		}, nil
	}

	s.zn.Lock()
	defer s.zn.Unlock()

	if len(req.LogLevel) != 0 && len(req.LogPath) == 0 && req.LogAge == 0 && req.RotationTime == 0 {
		level, err := logrus.ParseLevel(req.LogLevel)
		if err != nil {
			return nil, err
		}
		s.log.SetLevel(level)
		s.logConf.LogLevel = req.LogLevel
		return &rpcpb.LoggingInfo{
			LogLevel:     level.String(),
			LogPath:      path,
			LogAge:       s.logConf.LogAge,
			RotationTime: uint32(s.logConf.LogRotationTime),
		}, nil
	}

	if len(req.LogLevel) == 0 {
		return nil, LogLevelLengthIsZeroError
	}
	if req.LogAge == 0 {
		return nil, LogAgeIsZeroError
	}
	if req.RotationTime == 0 {
		return nil, RotationTimeIsZeroError
	}

	if req.RotationTime > req.LogAge {
		return nil, RotationTimeGreaterThanMaxAgeError
	}

	path = req.LogPath
	if len(path) == 0 {
		return nil, LogPathIsEmptyError
	}

	level, err := logrus.ParseLevel(req.LogLevel)
	if err != nil {
		return nil, err
	}

	if !filepath.IsAbs(path) {
		path, _ = filepath.Abs(path)
	}
	_, err = os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"path":  path,
				"error": err,
			}).Debug("create folder error")
			return nil, err
		}
	}

	hooker := logging.NewFileRotateHooker(path, int64(req.RotationTime), req.LogAge)
	for _, level := range hooker.Levels() {
		if level != logrus.TraceLevel {
			s.log.Hooks[level][1] = hooker
		} else {
			s.log.Hooks[level][0] = hooker
		}
	}
	//update level
	s.log.SetLevel(level)

	s.logConf.LogLevel = req.LogLevel
	s.logConf.LogAge = req.LogAge
	s.logConf.LogFile = req.LogPath
	s.logConf.LogRotationTime = int64(req.RotationTime)

	logInfo := &rpcpb.LoggingInfo{
		LogLevel:     level.String(),
		LogPath:      path,
		LogAge:       req.LogAge,
		RotationTime: uint32(req.RotationTime),
	}

	return logInfo, nil
}

//Return the key pair
func (s *AdminService) GeneratePrivateKey(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.PrivateKey, error) {
	privKey, err := crypto.NewPrivateKey(nil)
	if err != nil {
		return nil, err
	}
	bytes, err := privKey.Encoded()
	if err != nil {
		return nil, err
	}
	hexPrivKey := byteutils.Hex(bytes)
	return &rpcpb.PrivateKey{PriKey: hexPrivKey}, nil
}

func (s *AdminService) checkAndConvertValue(addr string, targetValue string) (*big.Int, error) {
	var value *big.Int
	var err error
	//some tx has not value, example fileTx, invokeTx and so on
	if len(targetValue) > 0 {
		value, err = core.CUintStringToNcUintBigInt(targetValue)
		if err != nil {
			return nil, err
		}

		zero := big.NewInt(0)
		worldState := s.cloudcard.BlockChain().FixedBlock().WorldState()
		//check balance
		if value.Cmp(zero) > 0 {
			acc, err := account.GetAccountByAddress(addr, worldState)
			if err != nil {
				return nil, err
			}
			if acc.Balance().Cmp(value) < 0 {
				logging.CLog().WithFields(logrus.Fields{
					"balance": acc.Balance().String(),
					"value:":  value.String(),
					"error":   BalanceNotEnoughError.Error(),
				}).Debug("check from address error")
				return nil, BalanceNotEnoughError
			}
		}

		if value.Cmp(zero) == 0 {
			value = nil
		}
	}
	return value, nil
}

func (s *AdminService) createTx(request *rpcpb.TransactionRequest) (*core.Transaction, error) {
	txPool := s.cloudcard.BlockChain().TxPool()
	if txPool == nil {
		return nil, TxPoolIsNilError
	}
	am := s.cloudcard.AccountManager()
	fromAddr, err := am.AddressIsValid(request.From)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"fromAddress": request.From,
			"error":       err,
		}).Debug("check from address error")
		return nil, err
	}

	var toAddr *core.Address
	if len(request.To) > 0 {
		toAddr, err = am.AddressIsValid(request.To)
		if err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"toAddress": request.To,
				"error":     err,
			}).Debug("check to address error")
			return nil, err
		}
	}

	priority := request.Priority
	if priority > core.PriorityHigh {
		logging.VLog().WithFields(logrus.Fields{
			"priority": priority,
		}).Debug("tx priority out of range")
		return nil, TxPriorityInvalidError
	}

	var data []byte
	if len(request.Data) > 0 {
		data, err = byteutils.FromHex(request.Data)
		if err != nil {
			logging.CLog().WithFields(logrus.Fields{
				"data:": request.Data,
				"error": DataIsNotHexStringError.Error(),
			}).Debug("hex data to bytes error")
			return nil, DataIsNotHexStringError
		}
	}

	value, err := s.checkAndConvertValue(request.From, request.Value)
	if err != nil {
		return nil, err
	}

	nonce := request.Nonce
	worldState, err := s.cloudcard.BlockChain().FixedBlock().WorldState().Copy()
	if err != nil {
		return nil, err
	}
	//cal account nonce
	acc, _ := account.GetAccountByAddress(request.From, worldState)
	if nonce == 0 {
		txPoolNonce := txPool.GetTxsNumByAddr(request.From)
		nonce = acc.Nonce() + uint64(txPoolNonce) + 1
	}

	if nonce <= acc.Nonce() {
		logging.VLog().WithFields(logrus.Fields{
			"txNonce:":    nonce,
			"acc.Nonce()": acc.Nonce(),
		}).Debug("tx nonce is less than or equal to account nonce")
		return nil, TxNonceLessThanAccountNonceError
	}

	chainId := s.cloudcard.BlockChain().ChainId()
	tx, err := core.NewTransaction(fromAddr, toAddr, value, nonce, chainId, priority, request.Type, data)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (s *AdminService) calculateNonce(addr string) uint64 {
	txPool := s.cloudcard.BlockChain().TxPool()
	worldState := s.cloudcard.BlockChain().FixedBlock().WorldState()
	//cal account nonce
	acc, _ := account.GetAccountByAddress(addr, worldState)
	txPoolNonce := txPool.GetTxsNumByAddr(addr)
	return acc.Nonce() + uint64(txPoolNonce) + 1
}
