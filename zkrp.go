/*
 * Copyright (C) 2019 ING BANK N.V.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Package zkrp creates and verifies zero-knowledge range proofs and set membership proofs.
//
// This package contains ING Bank's implementations of Bulletproofs, Zero Knowledge Range Proof (ZKRP) and Zero Knowledge Set Membership (ZKSM). The current implementations are based on the following papers:
//
//  * Range Proofs based on the paper: Efficient Proofs that a Committed Number Lies in an Interval by Fabrice Boudot.
//  * Set Membership Proofs based on the paper: Efficient protocols for set membership and range proofs, by Jan Camenisch, Rafik Chaabouni and Abhi Shelat.
//  * Bulletproofs based on paper: Bulletproofs: Short Proofs for Confidential Transactions and More, by Benedikt Bünz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille and Greg Maxwell.
//
// For details, see https://github.com/ing-bank/zkrp/blob/master/README.md
package zkrp
