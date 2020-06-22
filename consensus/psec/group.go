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

//
type Group struct {
	Master  string
	Members [3]string
}

//
func NewGroup() *Group {
	return &Group{
		Master:  "",
		Members: [3]string{},
	}
}

//
func (gp *Group) SetMaster(master string) {
	gp.Master = master
}

//
func (gp *Group) SetMembers(members []string) {
	if len(members) != 3 {
		return
	}
	for i, m := range gp.Members {
		gp.Members[i] = m
	}
}

//
func (gp *Group) GetMaster() string {
	return gp.Master
}

//
func (gp *Group) GetMembers() []string {
	res := make([]string, 0, 3)
	for _, m := range gp.Members {
		res = append(res, m)
	}
	return res
}
