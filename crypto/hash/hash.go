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
package hash

import (
	"crypto/sha256"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

//Sha3256 returns the SHA3-256 digest of the data.
func Sha3256(d ...[]byte) []byte {
	h := sha3.New256()
	for _, v := range d {
		h.Write(v)
	}

	return h.Sum(nil)
}

//Sha3512 returns the SHA3-512 digest of the data.
func Sha3512(d ...[]byte) []byte {
	h := sha3.New512()
	for _, v := range d {
		h.Write(v)
	}
	return h.Sum(nil)
}

// Sha256 returns the SHA-256 digest of the data.
func Sha256(args ...[]byte) []byte {
	hasher := sha256.New()
	for _, bytes := range args {
		hasher.Write(bytes)
	}
	return hasher.Sum(nil)
}

// Ripemd160 return the RIPEMD160 digest of the data.
func Ripemd160(d ...[]byte) []byte {
	h := ripemd160.New()
	for _, v := range d {
		h.Write(v)
	}
	return h.Sum(nil)
}
