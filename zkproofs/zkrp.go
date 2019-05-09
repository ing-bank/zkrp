// Copyright 2018 ING Bank N.V.
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

/*
This file contains the implementation of the ZKRP scheme proposed in the paper:
Efficient Protocols for Set Membership and Range Proofs
Jan Camenisch, Rafik Chaabouni, abhi shelat
Asiacrypt 2008
*/

package zkproofs

type izkrp interface {
	//Commit()
	Setup(a,b int64)
	Prove()
	Verify() (bool, error)
}


