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

import "errors"

// MessageType
const (
	MessageTypeNewBlock                   = "newblock"
	MessageTypeParentBlockDownloadRequest = "dlblock"
	MessageTypeBlockDownloadResponse      = "dlreply"
	MessageTypeNewTx                      = "newtx"
)

var (
	ErrInvalidAddress            = errors.New("address: invalid address")
	ErrInvalidAddressFormat      = errors.New("address: invalid address format")
	ErrInvalidAddressType        = errors.New("address: invalid address type")
	ErrInvalidAddressChecksum    = errors.New("address: invalid address checksum")
	ErrTxPoolFull                = errors.New("tx pool is full")
	ErrInvalidArgument           = errors.New("invalid argument(s)")
	ErrNilArgument               = errors.New("argument(s) is nil")
	ErrInvalidAmount             = errors.New("invalid amount")
	ErrInsufficientBalance       = errors.New("insufficient balance")
	ErrInvalidProtoToBlock       = errors.New("protobuf message cannot be converted into Block")
	ErrInvalidProtoToBlockHeader = errors.New("protobuf message cannot be converted into BlockHeader")
	ErrInvalidProtoToTransaction = errors.New("protobuf message cannot be converted into Transaction")
	ErrInvalidProtoToWitness     = errors.New("protobuf message cannot be converted into Witness")
	ErrInvalidProtoToPsecData    = errors.New("protobuf message cannot be converted into PsecData")
	ErrInvalidTransfer           = errors.New("transfer error: overflow or insufficient balance")
	ErrDuplicatedTransaction     = errors.New("duplicated transaction")
	ErrSmallTransactionNonce     = errors.New("cannot accept a transaction with smaller nonce")
	ErrLargeTransactionNonce     = errors.New("cannot accept a transaction with too bigger nonce")

	ErrDuplicatedBlock           = errors.New("duplicated block")
	ErrInvalidChainID            = errors.New("invalid transaction chainID")
	ErrInvalidTransactionHash    = errors.New("invalid transaction hash")
	ErrInvalidBlockHeaderChainID = errors.New("invalid block header chainId")
	ErrInvalidBlockHash          = errors.New("invalid block hash")
	ErrInvalidBlockSign          = errors.New("invalid block signature")

	ErrInvalidTransactionSigner = errors.New("invalid transaction signer")
	ErrInvalidTransactionSign   = errors.New("invalid transaction signature")
	ErrInvalidPublicKey         = errors.New("invalid public key")

	ErrMissingParentBlock                                = errors.New("cannot find the block's parent block in storage")
	ErrInvalidBlockCannotFindParentInLocalAndTrySync     = errors.New("invalid block received, sync its parent from others")
	ErrInvalidBlockCannotFindParentInLocalAndTryDownload = errors.New("invalid block received, download its parent from others")
	ErrLinkToWrongParentBlock                            = errors.New("link the block to a block who is not its parent")
	ErrCloneAccountState                                 = errors.New("failed to clone account state")

	ErrInvalidBlockStateRoot = errors.New("invalid block state root hash")
	ErrInvalidBlockTxsRoot   = errors.New("invalid block txs root hash")
)
