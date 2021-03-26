package main

import (
	"bytes"
	"crypto/ed25519"

	"golang.org/x/crypto/sha3"
)

// Asset is some data to add to the chain
type Asset struct {
	Data       []byte
	Signature  []byte
	PrevOwner  ed25519.PublicKey
	Owner      ed25519.PublicKey
	Creator    ed25519.PublicKey
	TransferID [32]byte
	Hash       [32]byte
}

func (m *Asset) serialize() []byte {
	return append(append(append(append(append(m.Data, m.PrevOwner...), m.Owner...), m.Creator...), m.Hash[:]...))
}

func (m *Asset) getTransferID() [32]byte {
	return sha3.Sum256(m.serialize())
}

func (m *Asset) sign(key ed25519.PrivateKey) {
	m.TransferID = m.getTransferID()
	m.Signature = ed25519.Sign(key, m.serialize())
}

func (m *Asset) verify() bool {
	txID := m.getTransferID()
	if !bytes.Equal(m.TransferID[:], txID[:]) {
		return false
	}

	dataID := sha3.Sum256(m.Data)
	if !bytes.Equal(m.Hash[:], dataID[:]) {
		return false
	}

	if !ed25519.Verify(m.PrevOwner, m.serialize(), m.Signature) {
		return false
	}

	return true
}
