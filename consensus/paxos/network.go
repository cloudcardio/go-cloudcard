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

import (
	"log"
	"time"
)

func CreateNetwork(nodes ...string) *network {
	nt := network{recvQueue: make(map[string]chan message, 0)}

	for _, node := range nodes {
		nt.recvQueue[node] = make(chan message, 1024)
	}

	return &nt
}

type network struct {
	recvQueue map[string]chan message
}

func (n *network) getNodeNetwork(id string) nodeNetwork {
	return nodeNetwork{id: id, net: n}
}

func (n *network) sendTo(m message) {
	log.Println("Send msg from:", m.from, " send to", m.to, " val:", m.val, " typ:", m.typ)
	n.recvQueue[m.to] <- m
}

func (n *network) recvFrom(id string) *message {
	select {
	case retMsg := <-n.recvQueue[id]:
		log.Println("Recev msg from:", retMsg.from, " send to", retMsg.to, " val:", retMsg.val, " typ:", retMsg.typ)
		return &retMsg
	case <-time.After(time.Second):
		//log.Println("id:", id, " don't get message.. time out.")
		return nil
	}
}

type nodeNetwork struct {
	id  string
	net *network
}

func (n *nodeNetwork) send(m message) {
	n.net.sendTo(m)
}

func (n *nodeNetwork) recv() *message {
	return n.net.recvFrom(n.id)
}
