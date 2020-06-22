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
package paxos

type msgType int

const (
	Prepare msgType = iota + 1 // Send from proposer -> acceptor
	Promise                    // Send from acceptor -> proposer
	Propose                    // Send from proposer -> acceptor
	Accept                     // Send from acceptor -> learner
)

type message struct {
	from   string
	to     string
	typ    msgType
	seq    int
	preSeq int
	val    string
}

func (m *message) getProposeVal() string {
	return m.val
}

func (m *message) getProposeSeq() int {
	return m.seq
}
