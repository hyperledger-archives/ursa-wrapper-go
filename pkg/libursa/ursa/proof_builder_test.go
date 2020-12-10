package ursa

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProofBuilder(t *testing.T) {
	t.Run("basic proof builder", func(t *testing.T) {
		pb, err := NewProofBuilder()
		assert.NoError(t, err)

		err = pb.AddCommonAttribute("master_secret")
		assert.NoError(t, err)

		nonce, err := NewNonce()
		assert.NoError(t, err)

		proof, err := pb.Finalize(nonce)
		assert.NoError(t, err)

		str, err := proof.ToJSON()
		assert.NoError(t, err)

		err = nonce.Free()
		assert.NoError(t, err)

		err = proof.Free()
		assert.NoError(t, err)

		newProof, err := ProofFromJSON(str)
		assert.NoError(t, err)
		assert.NotNil(t, newProof)

	})

	t.Run("with sub proof request", func(t *testing.T) {
		fields := []string{"attr1", "attr2", "attr3"}
		vals := map[string]interface{}{
			"attr1": "val1",
			"attr2": "val2",
			"attr3": "val3",
		}

		pb, err := NewProofBuilder()
		assert.NoError(t, err)

		err = pb.AddCommonAttribute("first_name")
		assert.NoError(t, err)

		subProofBuilder, err := NewSubProofRequestBuilder()
		assert.NoError(t, err)

		for _, field := range fields {
			err = subProofBuilder.AddRevealedAttr(field)
			assert.NoError(t, err)
		}

		subProof, err := subProofBuilder.Finalize()

		schema := createSchema(t, fields)

		var nonSchemaFields []string
		nonSchema := createNonSchema(t, nonSchemaFields)

		credDef, err := NewCredentialDef(schema, nonSchema, false)
		assert.NoError(t, err)

		values := createValues(t, vals)
		sig, _ := createSignature(t, fields, vals)

		err = pb.AddSubProofRequest(subProof, schema, nonSchema, sig, values, credDef.PubKey)
		assert.NoError(t, err)

		nonce, err := NewNonce()
		assert.NoError(t, err)

		proof, err := pb.Finalize(nonce)
		assert.NoError(t, err)

		str, err := proof.ToJSON()
		assert.NoError(t, err)

		result := map[string]interface{}{}
		err = json.Unmarshal(str, &result)
		assert.NoError(t, err)

		proofs, ok := result["proofs"].([]interface{})
		assert.True(t, ok)

		pp, ok := proofs[0].(map[string]interface{})
		assert.True(t, ok)

		primary, ok := pp["primary_proof"].(map[string]interface{})
		assert.True(t, ok)

		eq, ok := primary["eq_proof"].(map[string]interface{})
		assert.True(t, ok)

		revealed, ok := eq["revealed_attrs"].(map[string]interface{})
		assert.True(t, ok)

		for _, field := range fields {
			x, ok := revealed[field].(string)
			assert.True(t, ok)
			i := new(big.Int)
			_, ok = i.SetString(x, 10)
			assert.True(t, ok)
		}

		err = nonce.Free()
		assert.NoError(t, err)

		err = subProof.Free()
		assert.NoError(t, err)

		newProof, err := ProofFromJSON(str)
		assert.NoError(t, err)
		assert.NotNil(t, newProof)

		err = values.Free()
		assert.NoError(t, err)

	})
}

func TestSubProofRequest(t *testing.T) {
	t.Run("basic subproof", func(t *testing.T) {
		builder, err := NewSubProofRequestBuilder()
		assert.NoError(t, err)

		err = builder.AddRevealedAttr("name")
		assert.NoError(t, err)

		proof, err := builder.Finalize()
		assert.NoError(t, err)
		assert.NotNil(t, proof)

		err = proof.Free()
		assert.NoError(t, err)
	})
}
