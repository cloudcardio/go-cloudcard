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
package psec

type MessageType int

const (
	MsgTypePrepare MessageType = 2000 + iota
	MsgTypeCommit
)

// RequestMessage
type RequestMessage struct {
	SeqId     int64
	Timestamp int64
	Proposer  string
	Content   interface{}
}

// PrePrepareMessage
type PrePrepareMessage struct {
	ViewId int64
	SeqId  int64
	Digest string
	ReqMsg *RequestMessage
}

// InternalMessage
type InternalMessage struct {
	MsgType MessageType
	ViewId  int64
	SeqId   int64
	Digest  string
	NodeId  string
}

// ResponseMessage
type ResponseMessage struct {
	ViewId    int64
	Timestamp int64
	NodeId    string
	Result    string
}
