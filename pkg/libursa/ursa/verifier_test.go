package ursa

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifierVerify(t *testing.T) {
	t.Run("happy path from existing proof", func(t *testing.T) {
		schemaBuilder, err := NewCredentialSchemaBuilder()
		assert.NoError(t, err)
		err = schemaBuilder.AddAttr("sex")
		assert.NoError(t, err)
		schema, err := schemaBuilder.Finalize()
		assert.NoError(t, err)

		nonSchemaBuilder, err := NewNonCredentialSchemaBuilder()
		assert.NoError(t, err)
		err = nonSchemaBuilder.AddAttr("master_secret")
		assert.NoError(t, err)
		nonSchema, err := nonSchemaBuilder.Finalize()

		credDef, err := NewCredentialDef(schema, nonSchema, false)
		assert.NoError(t, err)
		assert.NotNil(t, credDef)

		masterSecret, err := NewMasterSecret()
		assert.NoError(t, err)
		js, err := masterSecret.ToJSON()
		assert.NoError(t, err)
		m := struct {
			MS string `json:"ms"`
		}{}
		err = json.Unmarshal(js, &m)
		assert.NoError(t, err)

		valuesBuilder, err := NewValueBuilder()
		assert.NoError(t, err)
		err = valuesBuilder.AddDecHidden("master_secret", m.MS)
		assert.NoError(t, err)
		err = valuesBuilder.AddDecKnown("sex", "5944657099558967239210949258394887428692050081607692519917050011144233115103")
		assert.NoError(t, err)

		values, err := valuesBuilder.Finalize()
		assert.NoError(t, err)

		credentialNonce, err := NewNonce()
		assert.NoError(t, err)

		blindedSecrets, err := BlindCredentialSecrets(credDef.PubKey, credDef.KeyCorrectnessProof, credentialNonce, values)
		assert.NoError(t, err)

		credentialIssuanceNonce, err := NewNonce()
		assert.NoError(t, err)

		p := SignatureParams{
			ProverID:                                 "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
			BlindedCredentialSecrets:                 blindedSecrets.Handle,
			BlindedCredentialSecretsCorrectnessProof: blindedSecrets.CorrectnessProof,
			CredentialIssuanceNonce:                  credentialIssuanceNonce,
			CredentialNonce:                          credentialNonce,
			CredentialValues:                         values,
			CredentialPubKey:                         credDef.PubKey,
			CredentialPrivKey:                        credDef.PrivKey,
		}

		credSig, credSigKP, err := p.SignCredential()
		assert.NoError(t, err)

		err = credSig.ProcessCredentialSignature(values, credSigKP, blindedSecrets.BlindingFactor, credDef.PubKey, credentialIssuanceNonce)
		assert.NoError(t, err)

		subProofBuilder, err := NewSubProofRequestBuilder()
		assert.NoError(t, err)
		err = subProofBuilder.AddRevealedAttr("sex")
		assert.NoError(t, err)
		subProofRequest, err := subProofBuilder.Finalize()
		assert.NoError(t, err)

		proofBuilder, err := NewProofBuilder()
		assert.NoError(t, err)
		err = proofBuilder.AddCommonAttribute("master_secret")
		assert.NoError(t, err)
		err = proofBuilder.AddSubProofRequest(subProofRequest, schema, nonSchema, credSig, values, credDef.PubKey)
		assert.NoError(t, err)

		proofRequestNonce, err := NewNonce()
		assert.NoError(t, err)

		proof, err := proofBuilder.Finalize(proofRequestNonce)
		assert.NoError(t, err)

		verifier, err := NewProofVerifier()
		assert.NoError(t, err)

		err = verifier.AddSubProofRequest(subProofRequest, schema, nonSchema, credDef.PubKey)
		assert.NoError(t, err)

		verified, err := verifier.Verify(proof, proofRequestNonce)
		assert.NoError(t, err)
		assert.True(t, verified)
	})
}
