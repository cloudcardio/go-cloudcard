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
package main

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/network"
	"fmt"
	"github.com/libp2p/go-libp2p-core/peer"
	"log"
	"os"
)

func main() {
	privateKeyPath := ""
	if len(os.Args) > 1 {
		privateKeyPath = os.Args[1]
	}

	networkKey, err := network.LoadNetworkKeyFromFileOrCreateNew(privateKeyPath)
	if err != nil {
		log.Fatal("create key error:", err)
	}

	keyStr, err := network.MarshalNetworkKey(networkKey)
	if err != nil {
		log.Fatal("marshal network key error:", err)
	}

	id, err := peer.IDFromPublicKey(networkKey.GetPublic())

	filename := id.String()

	f, err := os.Create(filename)
	if err != nil {
		log.Fatal("create file error:", err)
	}
	defer f.Close()

	_, err = f.Write([]byte(keyStr))
	if err != nil {
		log.Fatal("write key error:", err)
	}

	fmt.Println("network id:", filename)
	fmt.Println("successful generation...")
}
