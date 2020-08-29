package oaep

import (
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
	"github.com/miekg/pkcs11/p11"
)

var (
	errPublicModulus       = errors.New("crypto/rsa: missing public modulus")
	errPublicExponentSmall = errors.New("crypto/rsa: public exponent too small")
	errPublicExponentLarge = errors.New("crypto/rsa: public exponent too large")
)

// Encrypt encrypts the given message with RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
//
// The label parameter may contain arbitrary data that will not be encrypted,
// but which gives important context to the message. For example, if a given
// public key is used to decrypt two types of messages then distinct label
// values could be used to ensure that a ciphertext for one purpose cannot be
// used for another by an attacker. If not required it can be empty.
//
// The message must be no longer than the length of the public modulus minus
// twice the hash length, minus a further 2.
//
// NB this is compatible with Go 1.15 rsa.EncryptOAEP (which you can use).
//    but its here to maintain the symmetry of the operations.
func Encrypt(hash hash.Hash, random io.Reader, pub *rsa.PublicKey, plaintext []byte, label []byte) ([]byte, error) {
	m, err := doOEAP(hash, random, pub, plaintext, label)
	if err != nil {
		return nil, err
	}
	c := encrypt(new(big.Int), pub, m)
	return c.Bytes(), nil
}

// Decrypt decrypts ciphertext using RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.New() is a reasonable choice.
//
// The label parameter must match the value given when encrypting. See
// Encrypt for details.
func Decrypt(hash hash.Hash, random io.Reader, k int, priv *p11.PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_X_509, []byte{})
	em, err := priv.Decrypt(*mechanism, ciphertext)
	if err != nil {
		return nil, err
	}
	m := new(big.Int)
	m.SetBytes(em)
	return undoOAEP(hash, k, m, label)
}

// NB this should match Decrypt but using an rsa.PrivateKey.
func decryptTest(hash hash.Hash, random io.Reader, k int, priv *rsa.PrivateKey, ciphertext []byte, label []byte) ([]byte, error) {
	c := new(big.Int)
	c.SetBytes(ciphertext)
	m, err := decrypt(priv, c)
	if err != nil {
		return nil, err
	}
	return undoOAEP(hash, k, m, label)
}

func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

// decrypt performs an RSA decryption, resulting in a plaintext integer. If a
// random source is given, RSA blinding is used.
// NB the original code had RSA blinding here, BUT that was removed from here
//    because this code path is only used by the tests. this way its less code
//    to maintain. also remember that the real Decrypt does the operation on
//    the HSM (and the private key never leaves the HSM).
func decrypt(priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	if c.Cmp(priv.N) > 0 {
		err = errors.New("c.Cmp(priv.N) > 0")
		return
	}
	if priv.N.Sign() == 0 {
		err = errors.New("priv.N.Sign() == 0")
		return
	}

	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	return
}

// checkPub sanity checks the public key before we use it.
// We require pub.E to fit into a 32-bit integer so that we
// do not have different behavior depending on whether
// int is 32 or 64 bits. See also
// https://www.imperialviolet.org/2012/03/16/rsae.html.
func checkPub(pub *rsa.PublicKey) error {
	if pub.N == nil {
		return errPublicModulus
	}
	if pub.E < 2 {
		return errPublicExponentSmall
	}
	if pub.E > 1<<31-1 {
		return errPublicExponentLarge
	}
	return nil
}

// incCounter increments a four byte, big-endian counter.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

func doOEAP(hash hash.Hash, random io.Reader, pub *rsa.PublicKey, msg []byte, label []byte) (*big.Int, error) {
	if err := checkPub(pub); err != nil {
		return nil, err
	}
	hash.Reset()
	k := pub.Size()
	if len(msg) > k-2*hash.Size()-2 {
		return nil, rsa.ErrMessageTooLong
	}

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	em := make([]byte, k)
	seed := em[1 : 1+hash.Size()]
	db := em[1+hash.Size():]

	copy(db[0:hash.Size()], lHash)
	db[len(db)-len(msg)-1] = 1
	copy(db[len(db)-len(msg):], msg)

	_, err := io.ReadFull(random, seed)
	if err != nil {
		return nil, err
	}

	mgf1XOR(db, hash, seed)
	mgf1XOR(seed, hash, db)

	m := new(big.Int)
	m.SetBytes(em)

	return m, nil
}

func undoOAEP(hash hash.Hash, k int, m *big.Int, label []byte) ([]byte, error) {
	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	// We probably leak the number of leading zeros.
	// It's not clear that we can do anything about this.
	em := m.FillBytes(make([]byte, k))

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, hash, db)
	mgf1XOR(db, hash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, rsa.ErrDecryption
	}

	return rest[index+1:], nil
}
