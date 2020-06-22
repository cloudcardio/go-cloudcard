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

package network

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/util/config"
	"cloudcard.pro/cloudcardio/go-cloudcard/util/logging"
	"github.com/sirupsen/logrus"
)

// cloudcardService service for cloudcard p2p network
type cloudcardService struct {
	node       *Node
	dispatcher *Dispatcher
}

// NewcloudcardService create netService
func NewcloudcardService(conf *config.Config) (*cloudcardService, error) {
	netcfg := GetNetConfig(conf)

	if netcfg == nil {
		logging.CLog().Fatal("Failed to find network config in config file")
		return nil, ErrConfigLackNetWork
	}

	node, err := NewNode(NewP2PConfig(conf))
	if err != nil {
		return nil, err
	}

	ns := &cloudcardService{
		node:       node,
		dispatcher: NewDispatcher(),
	}
	node.SetcloudcardService(ns)

	return ns, nil
}

// PutMessage put message to dispatcher.
func (ns *cloudcardService) PutMessage(msg Message) {
	ns.dispatcher.PutMessage(msg)
}

// Start start p2p manager.
func (ns *cloudcardService) Start() error {
	logging.CLog().Info("Starting cloudcardService...")

	// start dispatcher.
	ns.dispatcher.Start()

	// start node.
	if err := ns.node.Start(); err != nil {
		ns.dispatcher.Stop()
		logging.CLog().WithFields(logrus.Fields{
			"err": err,
		}).Error("Failed to start cloudcardService.")
		return err
	}

	logging.CLog().Info("Started cloudcardService.")
	return nil
}

// Stop stop p2p manager.
func (ns *cloudcardService) Stop() {
	logging.CLog().Info("Stopping cloudcardService...")

	ns.node.Stop()
	ns.dispatcher.Stop()
}

// Register register the subscribers.
func (ns *cloudcardService) Register(subscribers ...*Subscriber) {
	ns.dispatcher.Register(subscribers...)
}

// Deregister Deregister the subscribers.
func (ns *cloudcardService) Deregister(subscribers ...*Subscriber) {
	ns.dispatcher.Deregister(subscribers...)
}

// Broadcast message.
func (ns *cloudcardService) Broadcast(name string, msg Serializable, priority int) {
	ns.node.BroadcastMessage(name, msg, priority)
}

// Relay message.
func (ns *cloudcardService) Relay(name string, msg Serializable, priority int) {
	ns.node.RelayMessage(name, msg, priority)
}

// SendMessage send message to a peer.
func (ns *cloudcardService) SendMessage(msgName string, msg []byte, target string, priority int) error {
	return ns.node.SendMessageToPeer(msgName, msg, priority, target)
}

// SendMessageToPeers send message to peers.
func (ns *cloudcardService) SendMessageToPeers(messageName string, data []byte, priority int, filter PeerFilterAlgorithm) []string {
	return ns.node.streamManager.SendMessageToPeers(messageName, data, priority, filter)
}

// SendMessageToPeer send message to a peer.
func (ns *cloudcardService) SendMessageToPeer(messageName string, data []byte, priority int, peerID string) error {
	return ns.node.SendMessageToPeer(messageName, data, priority, peerID)
}

// SendMessageToPeer send message to a peer.
func (ns *cloudcardService) SendMessageToPeerOrBroadcast(messageName string, messageContent Serializable, priority int, peerID string) error {
	return ns.node.SendMessageToPeerOrBroadcast(messageName, messageContent, priority, peerID)
}

// ClosePeer close the stream to a peer.
func (ns *cloudcardService) ClosePeer(peerID string, reason error) {
	ns.node.streamManager.CloseStream(peerID, reason)
}

// Node return the peer node
func (ns *cloudcardService) Node() *Node {
	return ns.node
}
