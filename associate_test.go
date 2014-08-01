package yesman

import (
	"testing"
)

func TestEncMacKey(t *testing.T) {
	a, err := NewAssociation(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(a.EncMacKey())
}
