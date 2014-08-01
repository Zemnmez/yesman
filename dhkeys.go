package yesman

import (
	"math/big"
	"math/rand"
)

//the pub and private key for this run.
var pubKey, prvKey *big.Int

//the two default mod and gen values, as multi-precision integers.
var defaultp, defaultg *big.Int

//the default mod 'p value' for key exchange
const defaultModStr = "155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443"

//the default gen 'g value' for key exchange
const defaultGen = 2


func init() {
	rr := rand.New(rand.NewSource(1337))
	defaultg = new(big.Int).SetInt64(defaultGen)
	var ok bool
	if defaultp, ok = new(big.Int).SetString(defaultModStr, 10); !ok{
		panic("Unable to parse mod string")
	}

	prvKey = new(big.Int).Rand(rr, defaultg)
	pubKey = new(big.Int).Exp(defaultg, prvKey, defaultp)
}

