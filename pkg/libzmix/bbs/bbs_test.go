package bbs

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

func TestGenerateKey(t *testing.T) {
	t.Run("GenerateKey", func(t *testing.T) {
		data := make([]byte, 4)
		rand.Read(data)
		kp, err := GenerateBlsKey(nil)

		assert.Empty(t, err)
		assert.NotEmpty(t, kp)
		assert.NotEmpty(t, kp.PublicKey)
		assert.NotEmpty(t, kp.SecretKey)

		kp.FreePublicKey()
		kp.FreeSecretKey()
	})
}

func TestBlsKeyPair(t *testing.T) {
	data := make([]byte, 4)
	rand.Read(data)
	blskp, err := GenerateBlsKey(data)
	assert.Empty(t, err)
	t.Run("BlsPublicKeyToBBSKey", func(t *testing.T) {
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(5)
		assert.Empty(t, err)
		assert.NotEmpty(t, bbsPublicKey)

		bbsPublicKey.Free()
	})

	blskp.FreeSecretKey()
	blskp.FreePublicKey()
}

func TestSignContextInit(t *testing.T) {
	t.Run("SignContextInit", func(t *testing.T) {
		handle, err := SignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, handle.data)
	})
}

func TestSignContext(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 31, 32}
	t.Run("SetPublicKey", func(t *testing.T) {
		signContext, err := SignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext.data)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)

		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(5)
		assert.Empty(t, err)

		err = signContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)
	})

	t.Run("SetSecretKey", func(t *testing.T) {
		signContext, err := SignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext.data)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)

		err = signContext.SetSecretKey(HandleByteBuffer{
			Buffer: blskp.SecretKey,
		})
		assert.Empty(t, err)
	})

	t.Run("AddMessageBytes", func(t *testing.T) {
		signContext, err := SignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext.data)

		err = signContext.AddMessages([]string{"a message", "another message", "the last message"})
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext)
	})

	t.Run("Finish full SignContext", func(t *testing.T) {
		signContext, err := SignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext.data)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(2)
		assert.Empty(t, err)

		err = signContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = signContext.SetSecretKey(HandleByteBuffer{
			Buffer: blskp.SecretKey,
		})
		assert.Empty(t, err)

		err = signContext.AddMessages([]string{"a message", "one more message"})
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext)

		signature, err := signContext.Finish()
		assert.Empty(t, err)
		assert.NotEmpty(t, signature)
		signature.Free()
	})

	t.Run("Should error if public key isn't set", func(t *testing.T) {
		signContext, err := SignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext.data)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)

		err = signContext.SetSecretKey(HandleByteBuffer{
			Buffer: blskp.SecretKey,
		})
		assert.Empty(t, err)

		err = signContext.AddMessages([]string{"a message"})
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext)

		signature, err := signContext.Finish()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Public Key must be set")
		assert.Empty(t, signature)
	})

	t.Run("Should error if secret key isn't set", func(t *testing.T) {
		signContext, err := SignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext.data)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(1)
		assert.Empty(t, err)

		err = signContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = signContext.AddMessages([]string{"a message"})
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext)

		signature, err := signContext.Finish()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Secret Key must be set")
		assert.Empty(t, signature)
	})

	t.Run("Should error if messages aren't set", func(t *testing.T) {
		signContext, err := SignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext.data)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(5)
		assert.Empty(t, err)

		err = signContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = signContext.SetSecretKey(HandleByteBuffer{
			Buffer: blskp.SecretKey,
		})
		assert.Empty(t, err)

		signature, err := signContext.Finish()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Messages cannot be empty")
		assert.Empty(t, signature)
	})
}

func TestBlindCommitmentContextInit(t *testing.T) {
	t.Run("BlindCommitmentContextInit", func(t *testing.T) {
		handle, err := BlindCommitmentContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, handle.data)
	})
}

func TestBlindCommitmentContext(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 31, 32}

	t.Run("Finish full BlindCommitmentContext", func(t *testing.T) {
		blindCommitmentContext, err := BlindCommitmentContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, blindCommitmentContext.data)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(3)
		assert.Empty(t, err)

		err = blindCommitmentContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		nonce, err := ursa.NewNonce()
		assert.Empty(t, err)
		nonceBytes, err := nonce.ToJSON()
		assert.Empty(t, err)
		err = blindCommitmentContext.SetNonce(nonceBytes)
		assert.Empty(t, err)

		err = blindCommitmentContext.AddMessage("a message", 0)
		assert.Empty(t, err)
		assert.NotEmpty(t, blindCommitmentContext)

		blindedCommitment, err := blindCommitmentContext.Finish()
		assert.Empty(t, err)
		assert.NotEmpty(t, blindedCommitment)
		assert.NotEmpty(t, blindedCommitment.BlindingFactor)
		assert.NotEmpty(t, blindedCommitment.Commitment)
		assert.NotEmpty(t, blindedCommitment.Context)
		blindedCommitment.Free()
	})
}

func TestVerifyBlindCommitmentContextInit(t *testing.T) {
	t.Run("VerifyBlindCommitmentContextInit", func(t *testing.T) {
		handle, err := VerifyBlindCommitmentContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, handle.data)
	})
}

func TestVerifyBlindCommitmentContext(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 31, 32}

	t.Run("SetPublicKey", func(t *testing.T) {
		verifyBlindCommitmentContext, err := VerifyBlindCommitmentContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, verifyBlindCommitmentContext.data)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(5)
		assert.Empty(t, err)

		err = verifyBlindCommitmentContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)
	})
	t.Run("SetNonceBytes", func(t *testing.T) {
		verifyBlindCommitmentContext, err := VerifyBlindCommitmentContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, verifyBlindCommitmentContext.data)

		nonce, err := ursa.NewNonce()
		assert.Empty(t, err)
		nonceBytes, err := nonce.ToJSON()
		assert.Empty(t, err)
		err = verifyBlindCommitmentContext.SetNonce(nonceBytes)
		assert.Empty(t, err)
	})

	t.Run("Finish", func(t *testing.T) {
		verifyBlindCommitmentContext, err := VerifyBlindCommitmentContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, verifyBlindCommitmentContext.data)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(5)
		assert.Empty(t, err)
		err = verifyBlindCommitmentContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		nonce, err := ursa.NewNonce()
		assert.Empty(t, err)
		nonceBytes, err := nonce.ToJSON()
		assert.Empty(t, err)
		err = verifyBlindCommitmentContext.SetNonce(nonceBytes)
		assert.Empty(t, err)

		err = verifyBlindCommitmentContext.AddBlinded(0)
		assert.Empty(t, err)

		blindedCommitment := createBlindedCommitment(t, *bbsPublicKey, nonceBytes, []string{"a message"})

		err = verifyBlindCommitmentContext.SetProof(HandleByteBuffer{Buffer: blindedCommitment.Context})
		assert.Empty(t, err)

		err = verifyBlindCommitmentContext.Finish()
		assert.Empty(t, err)
		blindedCommitment.Free()
	})
}

func TestBlindSignContext(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 31, 32}

	t.Run("full run", func(t *testing.T) {
		messages := []string{"a message", "another message", "one more message"}
		blindSignContext, err := BlindSignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, blindSignContext)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(3)
		assert.Empty(t, err)

		err = blindSignContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = blindSignContext.SetSecretKey(HandleByteBuffer{
			Buffer: blskp.SecretKey,
		})
		assert.Empty(t, err)

		err = blindSignContext.AddMessage(messages[0], 0)
		assert.Empty(t, err)
		assert.NotEmpty(t, blindSignContext)

		nonce, err := ursa.NewNonce()
		assert.Empty(t, err)
		assert.NotEmpty(t, nonce)

		nonceBytes, err := nonce.ToJSON()
		assert.Empty(t, err)
		assert.NotEmpty(t, nonceBytes)

		blindedCommitment := createBlindedCommitment(t, *bbsPublicKey, nonceBytes, messages)
		assert.NotEmpty(t, blindedCommitment)

		err = blindSignContext.SetCommitment(HandleByteBuffer{blindedCommitment.Commitment})
		assert.Empty(t, err)
		assert.NotEmpty(t, blindSignContext)

		blindedSignature, err := blindSignContext.Finish()
		assert.Empty(t, err)
		assert.NotEmpty(t, blindedSignature)

		unblindedSignature, err := blindedSignature.Unblind(HandleByteBuffer{blindedCommitment.BlindingFactor})
		assert.Empty(t, err)
		assert.NotEmpty(t, unblindedSignature)
		blindedCommitment.Free()
	})
}

func TestVerifyContext(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 31, 32}

	t.Run("verify unblinded signature", func(t *testing.T) {
		messages := []string{"a message", "another message", "one more message"}
		blindSignContext, err := BlindSignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, blindSignContext)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(3)
		assert.Empty(t, err)

		nonce, err := ursa.NewNonce()
		assert.Empty(t, err)
		assert.NotEmpty(t, nonce)

		nonceBytes, err := nonce.ToJSON()
		assert.Empty(t, err)
		assert.NotEmpty(t, nonceBytes)

		blindedCommitment := createBlindedCommitment(t, *bbsPublicKey, nonceBytes, messages)

		unblindedSignature := createUnblindedSignature(t, *bbsPublicKey, HandleByteBuffer{blskp.SecretKey}, messages[0], 0, *blindedCommitment)

		verifyContext, err := VerifyContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, verifyContext)

		err = verifyContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = verifyContext.SetSignature(unblindedSignature)
		assert.Empty(t, err)

		err = verifyContext.AddMessages([]string{"a message", "another message", "one more message"})
		assert.Empty(t, err)

		result, err := verifyContext.Finish()
		assert.True(t, result)
		assert.Empty(t, err)
	})

	t.Run("verify signature", func(t *testing.T) {
		messages := []string{"a message", "another message", "one more message"}
		blindSignContext, err := BlindSignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, blindSignContext)

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(3)
		assert.Empty(t, err)

		signature := createSignature(t, *bbsPublicKey, HandleByteBuffer{blskp.SecretKey}, messages)

		verifyContext, err := VerifyContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, verifyContext)

		err = verifyContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = verifyContext.SetSignature(signature)
		assert.Empty(t, err)

		err = verifyContext.AddMessages(messages)
		assert.Empty(t, err)

		result, err := verifyContext.Finish()
		assert.True(t, result)
		assert.Empty(t, err)
	})
}

func TestProofContext(t *testing.T) {
	t.Run("ProofContextInit", func(t *testing.T) {
		handle, err := ProofContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, handle.data)
	})

	t.Run("Full run of ProofContext", func(t *testing.T) {
		data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 2, 3, 4, 5, 6, 7, 8,
			9, 10, 31, 32}
		messages := []string{"a message", "another message", "the third message", "the fourth message", "the last message"}

		blskp, err := GenerateBlsKey(data)
		assert.Empty(t, err)
		bbsPublicKey, err := blskp.BlsPublicKeyToBBSKey(5)
		assert.Empty(t, err)

		signContext, err := SignContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, signContext)

		err = signContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = signContext.SetSecretKey(HandleByteBuffer{blskp.SecretKey})
		assert.Empty(t, err)

		err = signContext.AddMessages(messages)
		assert.Empty(t, err)

		signature, err := signContext.Finish()
		assert.Empty(t, err)
		assert.NotEmpty(t, signature)

		nonce, err := ursa.NewNonce()
		assert.Empty(t, err)
		assert.NotEmpty(t, nonce)

		nonceBytes, err := nonce.ToJSON()
		assert.Empty(t, err)
		assert.NotEmpty(t, nonceBytes)

		blindCommitmentContext, err := BlindCommitmentContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, blindCommitmentContext.data)

		err = blindCommitmentContext.AddMessage(messages[0], 0)
		assert.Empty(t, err)
		assert.NotEmpty(t, blindCommitmentContext)

		err = blindCommitmentContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = blindCommitmentContext.SetNonce(nonceBytes)
		assert.Empty(t, err)

		blindedCommitment, err := blindCommitmentContext.Finish()
		assert.Empty(t, err)

		verifyContext, err := VerifyBlindCommitmentContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, verifyContext)

		err = verifyContext.AddBlinded(0)
		assert.Empty(t, err)

		err = verifyContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = verifyContext.SetNonce(nonceBytes)
		assert.NoError(t, err)

		err = verifyContext.SetProof(HandleByteBuffer{blindedCommitment.Context})
		assert.Empty(t, err)

		err = verifyContext.Finish()
		assert.NoError(t, err)

		blindSignCtx, err := BlindSignContextInit()
		assert.NoError(t, err)

		for i, message := range messages[1:] {
			err := blindSignCtx.AddMessage(message, i+1)
			assert.NoError(t, err)
		}

		err = blindSignCtx.SetPublicKey(*bbsPublicKey)
		assert.NoError(t, err)

		err = blindSignCtx.SetSecretKey(HandleByteBuffer{blskp.SecretKey})
		assert.NoError(t, err)

		err = blindSignCtx.SetCommitment(HandleByteBuffer{blindedCommitment.Commitment})
		assert.NoError(t, err)

		blindedSignature, err := blindSignCtx.Finish()
		assert.NoError(t, err)

		unblindedSignature, err := blindedSignature.Unblind(HandleByteBuffer{blindedCommitment.BlindingFactor})
		assert.NoError(t, err)

		proofContext, err := ProofContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, proofContext.data)

		err = proofContext.AddProofMessages(messages[0:2], Revealed, HandleByteBuffer{blindedCommitment.BlindingFactor})
		assert.Empty(t, err)

		err = proofContext.AddProofMessages(messages[2:], HiddenProofSpecificBlinding, HandleByteBuffer{blindedCommitment.BlindingFactor})
		assert.Empty(t, err)

		err = proofContext.SetSignature(unblindedSignature)
		assert.Empty(t, err)

		err = proofContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = proofContext.SetNonce(nonceBytes)
		assert.NoError(t, err)

		proof, err := proofContext.Finish()
		assert.NoError(t, err)
		assert.NotEmpty(t, proof)

		verifyProofContext, err := VerifyProofContextInit()
		assert.Empty(t, err)
		assert.NotEmpty(t, verifyProofContext)

		err = verifyProofContext.AddMessage(messages[0], 0)
		assert.Empty(t, err)

		err = verifyProofContext.AddMessage(messages[1], 1)
		assert.Empty(t, err)

		err = verifyProofContext.SetNonce(nonceBytes)
		assert.Empty(t, err)

		err = verifyProofContext.SetPublicKey(*bbsPublicKey)
		assert.Empty(t, err)

		err = verifyProofContext.SetProof(HandleByteBuffer{Buffer: proof.Buffer})
		assert.Empty(t, err)

		err = verifyProofContext.Finish()
		assert.Empty(t, err)

	})
}

func createBlindedCommitment(t *testing.T, bbsPublicKey HandleByteBuffer, nonce []byte, messages []string) *BlindedCommitment {
	blindCommitmentContext, err := BlindCommitmentContextInit()
	assert.Empty(t, err)
	assert.NotEmpty(t, blindCommitmentContext.data)

	err = blindCommitmentContext.AddMessage(messages[0], 0)
	assert.Empty(t, err)
	assert.NotEmpty(t, blindCommitmentContext)

	err = blindCommitmentContext.SetPublicKey(bbsPublicKey)
	assert.Empty(t, err)

	err = blindCommitmentContext.SetNonce(nonce)
	assert.Empty(t, err)

	blindedCommitment, err := blindCommitmentContext.Finish()
	assert.Empty(t, err)

	return blindedCommitment
}

func createUnblindedSignature(t *testing.T, bbsPublicKey, secretKey HandleByteBuffer, message string, index int, blindedCommitment BlindedCommitment) *Signature {
	blindSignContext, err := BlindSignContextInit()
	assert.Empty(t, err)
	assert.NotEmpty(t, blindSignContext)

	err = blindSignContext.SetPublicKey(bbsPublicKey)
	assert.Empty(t, err)

	err = blindSignContext.SetSecretKey(secretKey)
	assert.Empty(t, err)

	err = blindSignContext.AddMessage(message, index)
	assert.Empty(t, err)
	assert.NotEmpty(t, blindSignContext)

	err = blindSignContext.SetCommitment(HandleByteBuffer{blindedCommitment.Commitment})
	assert.Empty(t, err)
	assert.NotEmpty(t, blindSignContext)

	blindedSignature, err := blindSignContext.Finish()
	assert.Empty(t, err)
	assert.NotEmpty(t, blindedSignature)

	unblindedSignature, err := blindedSignature.Unblind(HandleByteBuffer{blindedCommitment.BlindingFactor})
	assert.Empty(t, err)
	assert.NotEmpty(t, unblindedSignature)

	return unblindedSignature
}

func createSignature(t *testing.T, bbsPublicKey HandleByteBuffer, secretKey HandleByteBuffer, messages []string) *Signature {
	signContext, err := SignContextInit()
	assert.Empty(t, err)
	assert.NotEmpty(t, signContext.data)

	err = signContext.SetPublicKey(bbsPublicKey)
	assert.Empty(t, err)

	err = signContext.SetSecretKey(secretKey)
	assert.Empty(t, err)

	err = signContext.AddMessages(messages)
	assert.Empty(t, err)
	assert.NotEmpty(t, signContext)

	signature, err := signContext.Finish()
	assert.Empty(t, err)
	assert.NotEmpty(t, signature)

	return signature
}
