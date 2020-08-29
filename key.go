package oaep

import (
	"crypto/rsa"
	"errors"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

// GetKey return the RSA key with the given label.
// see https://github.com/ThalesIgnite/crypto11/blob/3d83a0a5d480dbbc8a65be3a111e194b5275e58b/rsa.go#L52-L81
func GetKey(session p11.Session, keyLabel string) (pub *rsa.PublicKey, priv *p11.PrivateKey, err error) {
	pub, err = getRSAPublicKey(session, keyLabel)
	if err != nil {
		return
	}
	priv, err = getRSAPrivateKey(session, keyLabel)
	return
}

// Get a RSA public key.
// see https://github.com/ThalesIgnite/crypto11/blob/3d83a0a5d480dbbc8a65be3a111e194b5275e58b/rsa.go#L52-L81
func getRSAPublicKey(session p11.Session, label string) (*rsa.PublicKey, error) {
	publicKeyObject, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil {
		return nil, err
	}

	n, err := publicKeyObject.Attribute(pkcs11.CKA_MODULUS)
	if err != nil {
		return nil, err
	}
	var modulus = new(big.Int)
	modulus.SetBytes(n)

	e, err := publicKeyObject.Attribute(pkcs11.CKA_PUBLIC_EXPONENT)
	if err != nil {
		return nil, err
	}

	var bigExponent = new(big.Int)
	bigExponent.SetBytes(e)
	if bigExponent.BitLen() > 32 {
		return nil, errors.New("Malformed RSA Public Key")
	}
	if bigExponent.Sign() < 1 {
		return nil, errors.New("Malformed RSA Public Key")
	}
	exponent := int(bigExponent.Uint64())

	result := &rsa.PublicKey{
		N: modulus,
		E: exponent,
	}
	if result.E < 2 {
		return nil, errors.New("Malformed RSA Public Key")
	}
	return result, nil
}

func getRSAPrivateKey(session p11.Session, label string) (*p11.PrivateKey, error) {
	// TODO https://github.com/miekg/pkcs11/issues/132
	privateKeyObject, err := session.FindObject([]*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	})
	if err != nil {
		return nil, err
	}
	p := p11.PrivateKey(privateKeyObject)
	return &p, nil
}
