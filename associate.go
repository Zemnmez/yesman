package yesman

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"sync/atomic"
	"time"
)

var assocHandleCounter uint64

func newAssocHandle() uint64 {
	return atomic.AddUint64(&assocHandleCounter, 1)
}

var associations = make(map[uint64]Association)


func Associate(f url.Values) (kv KeyValue, err error) {

	if t := f.Get("openid.assoc_type"); t != "" && t != "HMAC-SHA1" {
		err =  errors.New("Unsupported assoc_type.")
		return
	}

	if t := f.Get("openid.session_type"); t != "" && t != "DH-SHA1" {
		err =  errors.New("Unsupported session_type.")
		return
	}

	if m := f.Get("openid.dh_modulus"); m != "" {
		err =  errors.New("A differing p value is not supported")
		return
	}

	if gen := f.Get("openid.dh_gen"); gen != "" {
		err =  errors.New("A differeng g value is not supported")
		return
	}

	var (
		pubkey *big.Int
		pubKeyStr string
	)

	if pubKeyStr = f.Get("openid.dh_consumer_public"); pubKeyStr == "" {
		err = errors.New("Missing public key.")
		return
	}

	bt, err := base64.StdEncoding.DecodeString(pubKeyStr)

	if err != nil {
		err =  fmt.Errorf("Could not decode publickey base64: %s", err)
		return
	}

	SetSignedBytes(pubkey, bt)

	a, err := NewAssociation(pubKey)
	if err != nil {
		err = fmt.Errorf("Error creating Association: %s", err)
		return
	}

	kv = make(KeyValue, 7)

	kv["assoc_type"] = "HMAC-SHA1"

	kv["assoc_handle"] = fmt.Sprint("%d", a.ID)

	kv["expires_in"] = fmt.Sprint("%d", expiresAfter.Seconds())

	kv["session_type"] = "DH-SHA1"

	kv["dh_server_public"] = a.DhPublic()

	if kv["enc_mac_key"], err = a.EncMacKey(); err != nil {
		return
	}

	associations[a.ID] = a
	return
}

type Association struct {
	ID         uint64
	ForeignKey *big.Int
	Expiry     time.Time
	DhKey      *big.Int
	MacSecret  [10]byte
}

func NewAssociation(theirKey *big.Int) (a Association, err error) {
	a.ID = newAssocHandle()
	a.ForeignKey = theirKey

	a.Expiry = time.Now().Add(expiresAfter)

	//the key acquired (here) through diffie-hellman key exchange
	a.DhKey = new(big.Int).Exp(gBig, new(big.Int).Mul(a.ForeignKey, pubKey), defaultp)
	if _, err = rand.Read(a.MacSecret[:]); err != nil {
		return
	}

	return
}

const expiresAfter = 2 * time.Minute

const publickey = 3

var gBig = new(big.Int).SetInt64(3)

// SetSignedBytes sets the value of n to the big-endian two's complement
// value stored in the given data. If data[0]&80 != 0, the number
// is negative. If data is empty, the result will be 0.
func SetSignedBytes(n *big.Int, data []byte) {
	n.SetBytes(data)
	if len(data) > 0 && data[0]&0x80 > 0 {
		n.Sub(n, new(big.Int).Lsh(one, uint(len(data))*8))
	}
}

// SignedBytes returns the big-endian two's complement
// form of n.
func SignedBytes(n *big.Int) []byte {
	switch n.Sign() {
	case 0:
		return []byte{0}
	case 1:
		b := n.Bytes()
		if b[0]&0x80 > 0 {
			b = append([]byte{0}, b...)
		}
		return b
	case -1:
		length := uint(n.BitLen()/8+1) * 8
		b := new(big.Int).Add(n, new(big.Int).Lsh(one, length)).Bytes()
		// When the most significant bit is on a byte
		// boundary, we can get some extra significant
		// bits, so strip them off when that happens.
		if len(b) >= 2 && b[0] == 0xff && b[1]&0x80 != 0 {
			b = b[1:]
		}
		return b
	}
	panic("unreachable")
}

func (a Association) DhPublic() string {
	return base64.StdEncoding.EncodeToString(SignedBytes(new(big.Int).Exp(gBig, pubKey, defaultp)))
}

func (a Association) EncMacKey() (s string, err error) {
	h := sha1.New()

	//Value: base64(SHA1(btwoc(g ^ (xy) mod p)) XOR secret(assoc_handle))
	//which I think means XORing the hashed secret with our secret btwoc'd
	//why they decided to have a function called secret which is actually a
	//lookup to 'somewhere where we have our mac secret' I have no idea
	//also, secret isn't even defined in the spec, it's meant to be obvious
	//I suppose.
	if _, err = h.Write(SignedBytes(a.DhKey)); err != nil {
		return
	}

	//sha1 is 20 bytes just like our key
	bt := make([]byte, 20)
	bt = h.Sum(bt)

	//xor with our key
	for i, v := range bt {
		bt[i] = v ^ a.MacSecret[i]
	}

	//return the base64 encoded mac

	s = base64.StdEncoding.EncodeToString(bt)
	return

}
