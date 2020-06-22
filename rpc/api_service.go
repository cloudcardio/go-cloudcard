package rpc

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/account"
	"cloudcard.pro/cloudcardio/go-cloudcard/conf"
	"cloudcard.pro/cloudcardio/go-cloudcard/core"
	corepb "cloudcard.pro/cloudcardio/go-cloudcard/core/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/core/state"
	"cloudcard.pro/cloudcardio/go-cloudcard/crypto/ed25519"
	"cloudcard.pro/cloudcardio/go-cloudcard/network"
	rpcpb "cloudcard.pro/cloudcardio/go-cloudcard/rpc/pb"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"math/big"
)

const (
	hexHashLength   = 64
	hexPubKeyLength = 64
	hexSignLength   = 128
)

var (
	HashLengthIsNot128Error       = errors.New("hex hash length must be 128")
	SignLengthIsNot128Error       = errors.New("hex signature length must be 128")
	BlockHeightError              = errors.New("block height must be greater than 0")
	BlockNotExistError            = errors.New("block not exist")
	NoConfirmBlockError           = errors.New("no confirm block now")
	JsonTxHashIsNotHexStringError = errors.New("tx hash must be hex string")
	JsonTxValueInvalidError       = errors.New("tx value invalid")
	JsonTxFeeInvalidError         = errors.New("tx fee invalid")
	JsonTxChainIdInvalidError     = errors.New("tx chain id invalid")
	JsonTxTypeIsEmptyError        = errors.New("tx type is empty")
	TxPriorityInvalidError        = errors.New("tx priority out of rang")
	PubKeyLengthInvalidError      = errors.New("public key length is not 64")
	DataInvalidError              = errors.New("tx data must be hex string")
	PubKeyIsNotHexStringError     = errors.New("public key must be hex string")
	TxSignIsNotHexStringError     = errors.New("tx signature must be hex string")
	CalculateTxHashInvalidError   = errors.New("the calculated transaction hash is not equal to the transaction hash")
	CalculateTxFeeInvalidError    = errors.New("the calculated transaction fee is not equal to the transaction fee")
	VerifyTxSignError             = errors.New("verify signature failed")
)

type ApiService struct {
	chain *core.BlockChain
	cloudcard  core.cloudcard
}

func (api *ApiService) GetPendingTransactionsByPage(ctx context.Context, req *rpcpb.GetPendingTransactionsByPageRequest) (*rpcpb.PendingTransaction, error) {
	txs, err := api.chain.TxPool().GetPendingTransactionsByPage(uint(req.Page), uint(req.Limit))
	if err != nil {
		return nil, err
	}
	transactions := txsToRpcpbTxs(txs)

	return &rpcpb.PendingTransaction{Txs: transactions}, nil
}

func (api *ApiService) GetPendingTransactionsSize(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.PendingTransactionsSize, error) {
	pendingTxSize := api.chain.TxPool().GetPendingTxSize()
	return &rpcpb.PendingTransactionsSize{Size: uint64(pendingTxSize)}, nil
}

func (api *ApiService) GetBlockByHash(ctx context.Context, req *rpcpb.BlockHashAndFull) (*rpcpb.BlockResponse, error) {
	block, err := getBlockByHash(req.Hash, api.chain)
	if err != nil {
		return nil, err
	}
	bestBlockIndex, hashs := api.chain.GetIndexAndHashesByHeight(block.Height())
	if hashs == nil || len(hashs) == 0 || bestBlockIndex < 0 {
		return nil, BlockNotExistError
	}
	bestBlock := hashs[bestBlockIndex].String() == req.Hash
	blockResponse := blockToRpcpbBlockResponse(block, req.FullFillTransaction, bestBlock)
	return blockResponse, nil
}

func (api *ApiService) GetBestBlockHash(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.BlockHash, error) {
	bestBlockHash := api.chain.FixedBlock().Hash().String()
	return &rpcpb.BlockHash{Hash: bestBlockHash}, nil
}

// get max block height
func (api *ApiService) GetMaxHeight(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.BlockHeight, error) {
	maxHeight := api.chain.TailBlock().Height()
	return &rpcpb.BlockHeight{Height: maxHeight}, nil
}

// get best block by height
func (api *ApiService) GetBestBlockByHeight(ctx context.Context, req *rpcpb.BlockHeightAndFull) (*rpcpb.BlockResponse, error) {
	if req.Height == 0 {
		return nil, BlockHeightError
	}
	bestBlockIndex, hashs := api.chain.GetIndexAndHashesByHeight(req.Height)
	if hashs == nil || len(hashs) == 0 || bestBlockIndex < 0 {
		return nil, BlockNotExistError
	}
	bestBlockHash := hashs[bestBlockIndex].String()
	block, err := getBlockByHash(bestBlockHash, api.chain)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"blockHeight": req.Height,
			"blockHash":   bestBlockHash,
		}).Debug("get best block by hash error")
		return nil, err
	}
	blockResponse := blockToRpcpbBlockResponse(block, req.FullFillTransaction, true)
	return blockResponse, err
}

// get best block by height
func (api *ApiService) GetBlocksByHeight(ctx context.Context, req *rpcpb.BlockHeightAndFull) (*rpcpb.BlockListResponse, error) {
	if req.Height == 0 {
		return nil, BlockHeightError
	}
	blocks := api.chain.GetBlocksByHeight(req.Height)
	if blocks == nil || len(blocks) == 0 {
		return nil, BlockNotExistError
	}

	bestBlockIndex, hashs := api.chain.GetIndexAndHashesByHeight(req.Height)
	if hashs == nil || len(hashs) == 0 || bestBlockIndex < 0 {
		return nil, BlockNotExistError
	}
	blockListResponse := make([]*rpcpb.BlockResponse, len(blocks))

	bestBlockHash := hashs[bestBlockIndex].String()
	bestBlock := false
	for i, block := range blocks {
		bestBlock = bestBlockHash == block.Hash().String()
		blockListResponse[i] = blockToRpcpbBlockResponse(block, req.FullFillTransaction, bestBlock)
	}

	return &rpcpb.BlockListResponse{Blocks: blockListResponse}, nil
}

// get account info by address
func (api *ApiService) GetAccount(ctx context.Context, req *rpcpb.Address) (*rpcpb.AccountInfo, error) {
	if api.chain.FixedBlock() == nil {
		return nil, NoConfirmBlockError
	}
	worldState := api.chain.FixedBlock().WorldState()
	acc, err := account.GetAccountByAddress(req.Address, worldState)
	if err != nil {
		return nil, err
	}

	accountInfo := accountToRpcAccountInfo(acc)

	return accountInfo, nil
}

// get creditIndex by address
func (api *ApiService) GetCreditIndex(ctx context.Context, req *rpcpb.Address) (*rpcpb.CreditIndexResponse, error) {
	if api.chain.FixedBlock() == nil {
		return nil, NoConfirmBlockError
	}
	worldState := api.chain.FixedBlock().WorldState()
	acc, err := account.GetAccountByAddress(req.Address, worldState)
	if err != nil {
		return nil, err
	}
	creditIndex := &rpcpb.CreditIndexResponse{
		CreditIndex: core.ZeroString,
	}

	if acc.CreditIndex() != nil {
		creditIndex.CreditIndex = acc.CreditIndex().String()
	}
	return creditIndex, nil
}

// Return the block chain info
func (api *ApiService) GetBlockChainInfo(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.BlockChainInfo, error) {
	return &rpcpb.BlockChainInfo{
		ChainId:       api.chain.ChainId(),
		TailHeight:    api.chain.TailBlock().Height(),
		ConfirmHeight: api.chain.FixedBlock().Height(),
		BestBlockHash: api.chain.FixedBlock().Hash().String(),
		PendingTxSize: uint64(api.chain.TxPool().GetPendingTxSize()),
	}, nil
}

func (s *ApiService) GetTransactionByHash(ctx context.Context, req *rpcpb.TransactionHash) (*rpcpb.TransactionReceipt, error) {
	txReceipt, err := s.cloudcard.BlockChain().GetTransactionByHash(req.Hash)
	if err != nil {
		logging.CLog().WithFields(logrus.Fields{
			"txHash": req.Hash,
			"error":  err,
		}).Debug("get tx result is nil")
		return nil, err
	}

	return txToRpcTxRecepit(txReceipt)
}

func (s *ApiService) GetBalance(ctx context.Context, req *rpcpb.Address) (*rpcpb.BalanceResponse, error) {
	worldState := s.chain.FixedBlock().WorldState()
	acc, err := account.GetAccountByAddress(req.Address, worldState)
	if err != nil {
		return nil, err
	}
	balance := core.NcUnitToCUnitString(acc.Balance())
	frozenFund := core.NcUnitToCUnitString(acc.FrozenFund())
	pledgeFund := core.NcUnitToCUnitString(acc.PledgeFund())
	return &rpcpb.BalanceResponse{
		Balance:    balance,
		FrozenFund: frozenFund,
		PledgeFund: pledgeFund,
	}, nil
}

func (s *ApiService) GetTransactionByContractAddress(ctx context.Context, req *rpcpb.ContractAddressRequest) (*rpcpb.TransactionReceipt, error) {
	contractAddresss, err := s.cloudcard.AccountManager().AddressIsValid(req.ContractAddress)
	if err != nil {
		metricsUnlockFailed.Mark(1)
		return nil, err
	}
	tx, err := s.cloudcard.BlockChain().GetTransactionByContractAddress(contractAddresss)
	if err != nil {
		return nil, err
	}

	return txToRpcTxRecepit(tx)
}

// Return the p2p node info.
func (s *ApiService) GetActiveCount(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.ActiveCountResponse, error) {
	streamManager := s.cloudcard.NetService().Node().StreamManager()
	return &rpcpb.ActiveCountResponse{ActiveCount: streamManager.ActivePeersCount()}, nil
}

// Return the p2p node info.
func (s *ApiService) GetNetVersion(context.Context, *rpcpb.NonParamsRequest) (*rpcpb.NetVersion, error) {
	netConfig := network.GetNetConfig(s.cloudcard.Config())
	return &rpcpb.NetVersion{
		NetworkId:       netConfig.NetworkId,
		ClientVersion:   network.ClientVersion,
		ProtocolVersion: network.cloudcardProtocolID,
		Listen:          netConfig.Listen,
	}, nil
}

// NodeInfo is the RPC API handler.
func (s *ApiService) NodeInfo(ctx context.Context, req *rpcpb.NonParamsRequest) (*rpcpb.NodeInfoResponse, error) {
	node := s.cloudcard.NetService().Node()
	streamManager := s.cloudcard.NetService().Node().StreamManager()
	netVersion, _ := s.GetNetVersion(ctx, req)
	activeCount := streamManager.ActivePeersCount()

	nodeInfo := &rpcpb.NodeInfoResponse{
		Id:            node.ID(),
		Coinbase:      conf.GetChainConfig(s.cloudcard.Config()).Coinbase,
		TailHeight:    s.cloudcard.BlockChain().TailBlock().Height(),
		ConfirmHeight: s.cloudcard.BlockChain().FixedBlock().Height(),
		ChainId:       s.cloudcard.BlockChain().ChainId(),
		Synchronized:  node.Synchronized(),
		BucketSize:    int32(node.BucketSize()),
		NetVersion:    netVersion,
		ActiveCount:   activeCount,
	}

	ids := node.AllPeerIds()
	if ids != nil && len(ids) > 0 {
		peerIds := make([]string, len(ids))
		for i, id := range ids {
			peerIds[i] = id
		}
		nodeInfo.PeerIds = peerIds
	}
	return nodeInfo, nil
}

//send sign tx
func (s *ApiService) SendSignedTransaction(ctx context.Context, req *rpcpb.Transaction) (*rpcpb.BoolResponse, error) {
	coreTx, err := s.rpcpbTxToCoreTx(req)
	if err != nil {
		return nil, err
	}

	fee := coreTx.CalcFee()
	if coreTx.GetFee().Cmp(fee) != 0 {
		logging.VLog().WithFields(logrus.Fields{
			"cal fee": fee.String(),
			"fee":     req.Fee,
		}).Debug(CalculateTxFeeInvalidError.Error())
		return nil, CalculateTxFeeInvalidError
	}

	txHash, err := coreTx.CalcHash()
	if err != nil {
		return nil, err
	}
	if !coreTx.Hash().Equals(txHash) {
		logging.VLog().WithFields(logrus.Fields{
			"cal hash": byteutils.Hex(txHash),
			"txHash":   req.Hash,
		}).Debug(CalculateTxHashInvalidError.Error())
		return nil, CalculateTxHashInvalidError
	}

	sign := new(ed25519.Signature)
	result, err := sign.Verify(txHash, coreTx.GetSign())
	if !result {
		logging.VLog().WithFields(logrus.Fields{
			"address": req.From,
			"txHash":  req.Hash,
			"sign":    req.Signature,
		}).Debug("verify signature failed")
		return nil, VerifyTxSignError
	}

	err = s.cloudcard.BlockChain().TxPool().AddAndBroadcast(coreTx)
	if err != nil {
		return nil, err
	}
	return &rpcpb.BoolResponse{Result: true}, nil
}

func txsToRpcpbTxs(transactions []*core.Transaction) []*rpcpb.Transaction {
	txs := make([]*rpcpb.Transaction, len(transactions))
	for i, tx := range transactions {
		txs[i] = &rpcpb.Transaction{
			Hash:      tx.Hash().String(),
			From:      tx.From().String(),
			Nonce:     tx.Nonce(),
			Type:      tx.GetData().Type,
			Priority:  tx.Priority(),
			Timestamp: tx.Timestamp(),
			ChainId:   tx.ChainId(),
		}
		if tx.GetSign() != nil {
			txs[i].Signature = tx.GetHexSignature()
		}
		//nc unit to C unit
		txs[i].Fee = core.NcUnitToCUnitString(tx.GetFee())

		if tx.GetValue() != nil {
			txs[i].Value = core.NcUnitToCUnitString(tx.GetValue())
		}
		if tx.To() != nil {
			txs[i].To = tx.To().String()
		}
		if tx.GetData().Msg != nil && len(tx.GetData().Msg) > 0 {
			txs[i].Data = byteutils.Hex(tx.GetData().Msg)
		}
	}
	return txs
}

func txsToRpcpbTxHashs(transactions []*core.Transaction) []*rpcpb.Transaction {
	txs := make([]*rpcpb.Transaction, len(transactions))
	for i, tx := range transactions {
		txs[i] = &rpcpb.Transaction{
			Hash: tx.Hash().String(),
		}
	}
	return txs
}

func getBlockByHash(blockHash string, chain *core.BlockChain) (*core.Block, error) {
	blockHashBytes, err := byteutils.FromHex(blockHash)
	if err != nil {
		return nil, err
	}

	block, err := core.LoadBlockFromStorage(blockHashBytes, chain)
	return block, err
}

func blockToRpcpbBlockResponse(block *core.Block, fullFillTx bool, bestBlock bool) *rpcpb.BlockResponse {
	blockResponse := &rpcpb.BlockResponse{
		ChainId:       block.Header().ChainId(),
		Hash:          block.Hash().String(),
		BestBlock:     bestBlock,
		WitnessReward: block.Header().WitnessReward().String(),
		Coinbase:      block.Coinbase().String(),
		StateRoot:     block.StateRoot().String(),
		TxsRoot:       byteutils.Hex(block.Header().TxsRoot()),
		Height:        block.Height(),
		Timestamp:     block.Timestamp(),
		Extra:         string(block.Header().Extra()),
	}
	//for genesis block
	if block.ParentHash() != nil {
		blockResponse.ParentHash = block.ParentHash().String()
	}
	length := len(block.Txs())
	if length == 0 {
		logging.CLog().WithFields(logrus.Fields{
			"blockHash": block.Hash().String(),
		}).Debug("the block no transactions")
		return blockResponse
	}
	var txs []*rpcpb.Transaction
	if fullFillTx {
		txs = txsToRpcpbTxs(block.Txs())
	} else {
		txs = txsToRpcpbTxHashs(block.Txs())
	}

	blockResponse.Txs = txs
	return blockResponse
}

func txToRpcTxRecepit(txReceipt *core.TransactionReceipt) (*rpcpb.TransactionReceipt, error) {
	tx := txReceipt.Tx
	txResponse := &rpcpb.TransactionReceipt{
		Hash:         tx.Hash().String(),
		From:         tx.From().String(),
		Nonce:        tx.Nonce(),
		Type:         tx.GetData().Type,
		Priority:     tx.Priority(),
		ChainId:      tx.ChainId(),
		Timestamp:    tx.Timestamp(),
		Signature:    tx.GetHexSignature(),
		BlockHeight:  txReceipt.BlockHeight,
		BlockHash:    txReceipt.BlockHash,
		ErrorMessage: txReceipt.ErrorMessage,
		Status:       txReceipt.Status,
	}

	if tx.To() != nil {
		txResponse.To = tx.To().String()
	}

	if tx.GetValue() != nil {
		txResponse.Value = core.NcUnitToCUnitString(tx.GetValue())
	}
	txResponse.Fee = core.NcUnitToCUnitString(tx.GetFee())
	if tx.GetData().Msg != nil {
		txResponse.Data = byteutils.Hex(tx.GetData().Msg)
	}
	return txResponse, nil
}

func accountToRpcAccountInfo(account state.Account) *rpcpb.AccountInfo {
	//uint conversion
	balance := core.NcUnitToCUnitString(account.Balance())
	frozenFund := core.NcUnitToCUnitString(account.FrozenFund())
	pledgeFund := core.NcUnitToCUnitString(account.PledgeFund())

	accountInfo := &rpcpb.AccountInfo{
		Address:    account.Address().Base58(),
		Balance:    balance,
		FrozenFund: frozenFund,
		PledgeFund: pledgeFund,
		Nonce:      account.Nonce(),
	}

	if account.VarsHash() != nil {
		accountInfo.VariablesHash = account.VarsHash().String()
	}

	if account.CreditIndex() != nil {
		accountInfo.CreditIndex = account.CreditIndex().String()
	}

	permissions := account.Permissions()
	if permissions == nil || len(permissions) == 0 {
		return accountInfo
	}

	var rpcPerm *rpcpb.Permission
	rpcPermissions := make([]*rpcpb.Permission, len(permissions))
	i := 0
	for _, per := range permissions {
		if per == nil {
			continue
		}
		if len(per.AuthCategory) == 0 {
			continue
		}
		rpcPerm = new(rpcpb.Permission)
		rpcPerm.AuthCategory = per.AuthCategory

		length := len(per.AuthMessage)
		if length > 0 {
			authMessages := make([]string, length)
			for j, msg := range per.AuthMessage {
				//byte auth message to string
				authMessages[j] = string(msg)
			}
			rpcPerm.AuthMessage = authMessages
		}
		rpcPermissions[i] = rpcPerm
		i++
	}
	if len(rpcPermissions) < len(permissions) {
		endIndex := len(permissions) - len(rpcPermissions)
		rpcPermissions = rpcPermissions[:endIndex]
	}
	accountInfo.Permissions = rpcPermissions

	return accountInfo
}

func (s *ApiService) rpcpbTxToCoreTx(txRequest *rpcpb.Transaction) (*core.Transaction, error) {
	if len(txRequest.Hash) != hexHashLength {
		return nil, HashLengthIsNot128Error
	}
	if len(txRequest.Signature) != hexSignLength {
		return nil, SignLengthIsNot128Error
	}
	if len(txRequest.PubKey) != hexPubKeyLength {
		return nil, PubKeyLengthInvalidError
	}

	signBytes, err := byteutils.FromHex(txRequest.Signature)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error": err,
			"sign":  txRequest.Signature,
		}).Debug("tx signature is not hex string")
		return nil, TxSignIsNotHexStringError
	}

	hashBytes, err := byteutils.FromHex(txRequest.Hash)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error":  err,
			"txHash": txRequest.Hash,
		}).Debug("tx hash is not hex string")
		return nil, JsonTxHashIsNotHexStringError
	}

	var dataBytes []byte
	if len(txRequest.Data) > 0 {
		dataBytes, err = byteutils.FromHex(txRequest.Data)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"error": err,
				"data":  txRequest.Data,
			}).Debug("tx data is not hex string")
			return nil, DataInvalidError
		}
	}

	pubKeyBytes, err := byteutils.FromHex(txRequest.PubKey)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error":  err,
			"pubKey": txRequest.PubKey,
		}).Debug("tx public key is not hex string")
		return nil, PubKeyIsNotHexStringError
	}

	am := s.cloudcard.AccountManager()
	from, err := am.AddressIsValid(txRequest.From)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"error": err,
			"from":  txRequest.From,
		}).Debug("from address invalid")
		return nil, err
	}

	var to *core.Address
	if len(txRequest.To) > 0 {
		to, err = am.AddressIsValid(txRequest.To)
		if err != nil {
			logging.VLog().WithFields(logrus.Fields{
				"error": err,
				"to":    txRequest.To,
			}).Debug("to address invalid")
			return nil, err
		}
	}

	var value *big.Int
	if len(txRequest.Value) > 0 {
		success := true
		value, success = new(big.Int).SetString(txRequest.Value, 0)
		if !success {
			logging.VLog().WithFields(logrus.Fields{
				"value": txRequest.Value,
			}).Debug("to address invalid")
			return nil, JsonTxValueInvalidError
		}
	}

	chainId := s.cloudcard.BlockChain().ChainId()
	if txRequest.ChainId != chainId {
		logging.VLog().WithFields(logrus.Fields{
			"blockchain id":   chainId,
			"jsonTx chain Id": txRequest.ChainId,
		}).Debug("to address invalid")
		return nil, JsonTxChainIdInvalidError
	}

	fee, success := new(big.Int).SetString(txRequest.Fee, 0)
	if !success {
		logging.VLog().WithFields(logrus.Fields{
			"fee": txRequest.Fee,
		}).Debug("to address invalid")
		return nil, JsonTxFeeInvalidError
	}

	if len(txRequest.Type) == 0 {
		return nil, JsonTxTypeIsEmptyError
	}

	err = core.CheckTxType(txRequest.Type)
	if err != nil {
		logging.VLog().WithFields(logrus.Fields{
			"txType": txRequest.Type,
		}).Debug(err.Error())
		return nil, err
	}

	priority := txRequest.Priority
	if priority > core.PriorityHigh {
		logging.VLog().WithFields(logrus.Fields{
			"priority": priority,
		}).Debug("tx priority out of range")
		return nil, TxPriorityInvalidError
	}

	corePbTx := &corepb.Transaction{
		Hash:      hashBytes,
		From:      from.Bytes(),
		Nonce:     txRequest.Nonce,
		ChainId:   chainId,
		Fee:       fee.Bytes(),
		Timestamp: txRequest.Timestamp,
		Priority:  priority,
	}
	if to != nil {
		corePbTx.To = to.Bytes()
	}
	if value != nil {
		corePbTx.Value = value.Bytes()
	}

	//Data
	data := &corepb.Data{
		Type: txRequest.Type,
		Msg:  dataBytes,
	}
	corePbTx.Data = data

	//signature
	signature := &corepb.Signature{
		Signer: pubKeyBytes,
		Data:   signBytes,
	}
	corePbTx.Sign = signature

	coreTx := new(core.Transaction)
	err = coreTx.FromProto(corePbTx)
	if err != nil {
		return nil, err
	}
	return coreTx, nil
}
