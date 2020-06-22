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

import (
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"math/big"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    *Address
		wantErr bool
	}{
		{
			"invalid checksum",
			args{"5ks9uWNo3WyfDWdVV9xGqg8aSk6TDi889vCoB"},
			nil,
			false,
		},
		{
			"beyond base58 alphabet",
			args{"5ks9uWNo3WyfDWwVV9xGqg8aSk6TDi889vCoB"},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AddressParse(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddressParse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AddressParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewAddress(t *testing.T) {
	type args struct {
		s []byte
	}
	tests := []struct {
		name    string
		args    args
		want    *Address
		wantErr bool
	}{
		{
			"genesis address",
			args{make([]byte, PublicKeyDataLength)},
			&Address{
				// 5ks9uWNo3WyfDWwVV9xGqg8aSk6TDi889vCoB
				address: []byte{35, 49, 1, 31, 185, 52, 219, 123, 90, 141, 18, 150, 2, 238, 90, 246, 63, 157, 200, 210, 75, 140, 233, 136, 239, 235, 106},
			},
			false,
		},
	}
	fmt.Println(new(big.Int).SetBytes([]byte{25, 87}).Int64())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := base58.Decode("c")
			fmt.Println(b)
			fmt.Println(base58.Encode([]byte{25}))
			got, err := NewAddressFromPublicKey(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			fmt.Println(got.Bytes())
			fmt.Println(len(got.String()))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddressGetType(t *testing.T) {
	tests := []struct {
		address string
		want    AddressType
	}{
		{"5ks9uWNo3WyfDWwVV9xGqg8aSk6TDi889vCoB", AccountAddress},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			addr, err := AddressParse(tt.address)
			assert.Nil(t, err)
			assert.NotNil(t, addr)
			assert.Equal(t, tt.want, addr.Type())
		})
	}
}
