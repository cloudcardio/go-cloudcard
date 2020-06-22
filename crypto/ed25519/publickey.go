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
package ed25519

import "cloudcard.pro/cloudcardio/go-cloudcard/crypto/keystore"

type PublicKey struct {
	pub []byte
}

func NewPublicKey(pub []byte) *PublicKey {
	pubKey := &PublicKey{pub}
	return pubKey
}

// Algorithm algorithm name
func (k *PublicKey) Algorithm() keystore.Algorithm {
	return keystore.ED25519
}

// Encoded encoded to byte
func (k *PublicKey) Encoded() ([]byte, error) {
	return k.pub, nil
}

// Decode decode data to key
func (k *PublicKey) Decode(data []byte) error {
	k.pub = data
	return nil
}

// Clear clear key content
func (k *PublicKey) Clear() {
	for i := range k.pub {
		k.pub[i] = 0
	}
}

// Verify verify ecdsa publickey
func (k *PublicKey) Verify(hash []byte, signature []byte) bool {
	return Verify(k.pub, hash, signature)
}
