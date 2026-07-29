package transfer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// ID uniquely identifies a transfer across reconnects so resume can continue
// from the last acknowledged byte offset.
type ID [16]byte

// NewID returns a cryptographically random transfer ID.
func NewID() (ID, error) {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		return ID{}, err
	}
	return id, nil
}

// String returns the ID as 32 lowercase hex characters.
func (id ID) String() string {
	return hex.EncodeToString(id[:])
}

// ParseID parses a 32-character hex transfer ID.
func ParseID(s string) (ID, error) {
	var id ID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return ID{}, fmt.Errorf("transfer: invalid id %q", s)
	}
	copy(id[:], b)
	return id, nil
}
