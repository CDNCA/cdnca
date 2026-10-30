package entitlement

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"filippo.io/edwards25519"
)

var errInvalidEd25519PublicKey = errors.New("invalid Ed25519 public key")

var ed25519PrimeSubgroupOrder = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

func ValidateEd25519PublicKey(publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errInvalidEd25519PublicKey
	}
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil || !bytes.Equal(point.Bytes(), publicKey) {
		return errInvalidEd25519PublicKey
	}
	identity := edwards25519.NewIdentityPoint()
	if point.Equal(identity) == 1 || multiplyByEd25519PrimeSubgroupOrder(point).Equal(identity) != 1 {
		return errInvalidEd25519PublicKey
	}
	return nil
}

func multiplyByEd25519PrimeSubgroupOrder(point *edwards25519.Point) *edwards25519.Point {
	result := edwards25519.NewIdentityPoint()
	addend := new(edwards25519.Point).Set(point)
	for _, value := range ed25519PrimeSubgroupOrder {
		for bit := 0; bit < 8; bit++ {
			if value&(1<<bit) != 0 {
				result.Add(result, addend)
			}
			addend.Add(addend, addend)
		}
	}
	return result
}
