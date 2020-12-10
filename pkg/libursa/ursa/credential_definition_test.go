package ursa

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCredentialDefinition(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		fields := []string{"attr1", "attr2", "attr3"}
		var nonfields []string

		credDef := createCredentialDefinition(t, fields, nonfields)

		pubKeyJSON, err := credDef.PubKey.ToJSON()
		assert.NoError(t, err)
		m := map[string]interface{}{}
		err = json.Unmarshal(pubKeyJSON, &m)
		assert.NoError(t, err)

		pkey, ok := m["p_key"].(map[string]interface{})
		assert.True(t, ok)

		r, ok := pkey["r"].(map[string]interface{})
		assert.True(t, ok)

		for _, field := range fields {
			x, ok := r[field].(string)
			assert.True(t, ok)
			i := new(big.Int)
			_, ok = i.SetString(x, 10)
			assert.True(t, ok)
		}

		privKeyJSON, err := credDef.PrivKey.ToJSON()
		assert.NoError(t, err)
		assert.NotEmpty(t, privKeyJSON)

		correctnessJSON, err := credDef.PubKey.ToJSON()
		assert.NoError(t, err)

		m = map[string]interface{}{}
		err = json.Unmarshal(correctnessJSON, &m)
		assert.NoError(t, err)

		pkey, ok = m["p_key"].(map[string]interface{})
		assert.True(t, ok)

		r, ok = pkey["r"].(map[string]interface{})
		assert.True(t, ok)

		for _, field := range fields {
			x, ok := r[field].(string)
			assert.True(t, ok)
			i := new(big.Int)
			_, ok = i.SetString(x, 10)
			assert.True(t, ok)
		}

		err = credDef.PubKey.Free()
		assert.NoError(t, err)

		err = credDef.PrivKey.Free()
		assert.NoError(t, err)

		err = credDef.KeyCorrectnessProof.Free()
		assert.NoError(t, err)
	})
}

func createCredentialDefinition(t *testing.T, fields, nonfields []string) *CredentialDef {

	fields = append(fields, "master_secret")

	schema := createSchema(t, fields)

	nonschema := createNonSchema(t, nonfields)

	credDef, err := NewCredentialDef(schema, nonschema, false)
	assert.NoError(t, err)

	return credDef
}

func createSchema(t *testing.T, fields []string) *CredentialSchemaHandle {
	schemaBuilder, err := NewCredentialSchemaBuilder()
	assert.NoError(t, err)

	for _, field := range fields {
		err = schemaBuilder.AddAttr(field)
		assert.NoError(t, err)
	}

	schema, err := schemaBuilder.Finalize()
	assert.NoError(t, err)

	return schema
}

func createNonSchema(t *testing.T, fields []string) *NonCredentialSchemaHandle {
	nonSchemaBuilder, err := NewNonCredentialSchemaBuilder()
	assert.NoError(t, err)

	for _, field := range fields {
		err = nonSchemaBuilder.AddAttr(field)
		assert.NoError(t, err)
	}

	nonSchema, err := nonSchemaBuilder.Finalize()
	assert.NoError(t, err)

	return nonSchema
}

func createValues(t *testing.T, values map[string]interface{}) *CredentialValues {
	builder, err := NewValueBuilder()
	assert.NoError(t, err)

	for k, v := range values {
		err = builder.AddDecKnown(k, EncodeValue(v))
		assert.NoError(t, err)
	}

	value, err := builder.Finalize()
	assert.NoError(t, err)

	return value
}
