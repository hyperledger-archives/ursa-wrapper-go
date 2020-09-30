package ursa

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestNewNonce(t *testing.T) {
	t.Run("NewNonce", func(t *testing.T) {
		n, err := NewNonce()
		assert.NotEmpty(t, n)
		assert.Empty(t, err)
	})
}

func TestNonceFromJson(t *testing.T) {
	t.Run("NonceFromJson", func(t *testing.T) {
		n, err := NonceFromJson("123456")
		if  n == nil {
			t.Errorf("NewNonce() returned blank value")
		}

		if err != nil {
			t.Errorf("NewNonce() returned error")
		}
	})

	t.Run("NonceFromJson", func(t *testing.T) {
		n, err := NonceFromJson("should_error")
		assert.Empty(t, n)
		assert.NotEmpty(t, err)
	})
}