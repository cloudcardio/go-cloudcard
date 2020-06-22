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
package cdb

import (
	"encoding/binary"
	"testing"
)

func Int64ToBytes(i int64) []byte {
	var buf = make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}
func Test_levelDb(t *testing.T) {
	//ldb, err := NewLDBMgr("e:\\ledb", 16, 16, "")
	//if err == nil {
	//	for i := 0; i < 10000000; {
	//		ldb.Put(Int64ToBytes(rand.Int63()), Int64ToBytes(rand.Int63()))
	//		i++
	//	}
	//	ldb.Close()
	//	//ldb.Put([]byte("hello2"), []byte("234fewq342323-1`232323213240968-543231432423142356756"))
	//
	//	//v,e:= ldb.Get([]byte("hello"))
	//	//if e == nil{
	//	//	fmt.Println(string(v))
	//	//}
	//} else {
	//	fmt.Println(err)
	//}

}
