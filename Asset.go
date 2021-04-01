package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Position denotes where an asset is located on the chain
type Position struct {
	BlockHash [32]byte
	Index     int
}

// Asset is some data to add to the chain
type Asset struct {
	Signature  []byte
	PrevTx     Position
	Owner      ed25519.PublicKey
	Creator    ed25519.PublicKey
	TransferID [32]byte
	Hash       [32]byte
}

func (m *Asset) serialize() []byte {
	return append(append(m.Owner, m.Creator...), m.Hash[:]...)
}

func (m *Asset) getTransferID() [32]byte {
	return sha3.Sum256(m.serialize())
}

func (m *Asset) sign(key ed25519.PrivateKey) {
	m.TransferID = m.getTransferID()
	m.Signature = ed25519.Sign(key, m.TransferID[:])
}

func (m *Asset) verify() bool {
	txID := m.getTransferID()
	if !bytes.Equal(m.TransferID[:], txID[:]) {
		fmt.Println("Bad tx id")
		return false
	}

	if m.PrevTx == (Position{}) {
		if !bytes.Equal(m.Creator, m.Owner) {
			return false
		}
	}

	return true
}
