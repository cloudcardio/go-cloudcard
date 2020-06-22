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

package cipher

import (
	"cloudcard.pro/cloudcardio/go-cloudcard/util/byteutils"
	"reflect"
	"testing"
)

func TestScrypt_Encrypt(t *testing.T) {
	passphrase := []byte("passphrase")
	hash1, _ := byteutils.FromHex("0eb3be2db3a534c192be5570c6c42f59")
	hash2, _ := byteutils.FromHex("5e6d587f26121f96a07cf4b8b569aac1")
	hash3, _ := byteutils.FromHex("c7174759e86c59dcb7df87def82f61eb")

	scrypt := new(Scrypt)
	tests := []struct {
		name string
		data []byte
	}{
		{
			"test1",
			hash1,
		},
		{
			"test2",
			hash2,
		},
		{
			"test3",
			hash3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := scrypt.Encrypt(tt.data, passphrase)
			if err != nil {
				t.Errorf("Encrypt() error = %v", err)
				return
			}
			want, err := scrypt.Decrypt(got, passphrase)
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
				return
			}
			if !reflect.DeepEqual(tt.data, want) {
				t.Errorf("Decrypt() = %v, data %v", want, tt.data)
			}
		})
	}
}
