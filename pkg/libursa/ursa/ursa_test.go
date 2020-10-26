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
		if n == nil {
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

func TestCredentialKeyCorrectnessProofFromJSON(t *testing.T) {
	t.Run("CredentialKeyCorrectnessProofFromJSON", func(t *testing.T) {
		correctnessProof, err := CredentialKeyCorrectnessProofFromJSON("bad string")
		assert.NotEmpty(t, err)
		assert.Empty(t, correctnessProof)
	})
}

func TestBlindedCredentialSecretsCorrectnessProofFromJSON(t *testing.T) {
	t.Run("BlindedCredentialSecretsCorrectnessProofFromJSON", func(t *testing.T) {
		correctnessProof, err := BlindedCredentialSecretsCorrectnessProofFromJSON("should error")
		assert.NotEmpty(t, err)
		assert.Empty(t, correctnessProof)
	})
}

func TestBlindedCredentialSecretsFromJSON(t *testing.T) {
	t.Run("BlindedCredentialSecretsFromJSON", func(t *testing.T) {
		credentialSecrets, err := BlindedCredentialSecretsFromJSON("should error")
		assert.NotEmpty(t, err)
		assert.Empty(t, credentialSecrets)
	})
	//	will test positive test case once C.ursa_cl_prover_blind_credential_secrets is wrapped
}