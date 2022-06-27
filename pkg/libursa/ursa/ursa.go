package ursa

/*
   #cgo LDFLAGS: -lursa
   #include "ursa_cl.h"
   #include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"unsafe"

	"github.com/pkg/errors"
)

type Handle struct {
	ptr unsafe.Pointer
}

type Nonce Handle

// NewNonce creates a random nonce
func NewNonce() (*Nonce, error) {
	var nonce unsafe.Pointer

	result := C.ursa_cl_new_nonce(&nonce)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &Nonce{nonce}, nil
}

// NonceFromJSON creates and returns nonce from json
func NonceFromJSON(jsn string) (*Nonce, error) {
	var handle unsafe.Pointer
	cjson := C.CString(jsn)
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_nonce_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &Nonce{handle}, nil
}

// ToJSON returns JSON representation of nonce
func (r *Nonce) ToJSON() ([]byte, error) {
	var d *C.char
	defer C.free(unsafe.Pointer(d))

	result := C.ursa_cl_nonce_to_json(r.ptr, &d)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	out := []byte(C.GoString(d))
	return out, nil
}

// Free deallocates the nonce
func (r *Nonce) Free() error {
	result := C.ursa_cl_nonce_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// BlindedCredentialSecretsCorrectnessProofFromJSON creates and returns blinded credential secrets correctness proof json.
func BlindedCredentialSecretsCorrectnessProofFromJSON(jsn []byte) (*BlindedCredentialSecretsCorrectnessProof, error) {
	var handle unsafe.Pointer
	cjson := C.CString(string(jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_blinded_credential_secrets_correctness_proof_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &BlindedCredentialSecretsCorrectnessProof{handle}, nil
}

// CredentialKeyCorrectnessProofFromJSON creates and returns credential key correctness proof from json
func CredentialKeyCorrectnessProofFromJSON(jsn []byte) (*CredentialDefKeyCorrectnessProof, error) {
	var handle unsafe.Pointer
	cjson := C.CString(string(jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_credential_key_correctness_proof_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialDefKeyCorrectnessProof{handle}, nil
}

// BlindedCredentialSecretsFromJSON creates and returns blinded credential secrets from json
func BlindedCredentialSecretsFromJSON(jsn []byte) (*BlindedCredentialSecretsHandle, error) {
	var handle unsafe.Pointer
	cjson := C.CString(string(jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_blinded_credential_secrets_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &BlindedCredentialSecretsHandle{handle}, nil
}

// CredentialPrivateKeyFromJSON creates and returns credential private key from json
func CredentialPrivateKeyFromJSON(jsn []byte) (*CredentialDefPrivKey, error) {
	var handle unsafe.Pointer
	cjson := C.CString(string(jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_credential_private_key_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialDefPrivKey{handle}, nil
}

// CredentialPublicKeyFromJSON creates and returns credential public key from json
func CredentialPublicKeyFromJSON(jsn []byte) (*CredentialDefPubKey, error) {
	var handle unsafe.Pointer
	cjson := C.CString(string(jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_credential_public_key_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialDefPubKey{handle}, nil
}

type NonCredentialSchemaBuilder Handle
type NonCredentialSchemaHandle Handle

// NewNonCredentialSchemaBuilder creates and returns non credential schema builder
func NewNonCredentialSchemaBuilder() (*NonCredentialSchemaBuilder, error) {
	var nonBuilder unsafe.Pointer

	result := C.ursa_cl_non_credential_schema_builder_new(&nonBuilder)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &NonCredentialSchemaBuilder{nonBuilder}, nil
}

// AddAttr adds new attribute to non credential schema
func (r *NonCredentialSchemaBuilder) AddAttr(attr string) error {
	cAttr := C.CString(attr)
	defer C.free(unsafe.Pointer(cAttr))

	result := C.ursa_cl_non_credential_schema_builder_add_attr(r.ptr, cAttr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// Finalize deallocates non_credential schema builder and returns non credential schema entity instead
func (r *NonCredentialSchemaBuilder) Finalize() (*NonCredentialSchemaHandle, error) {
	var nonSchema unsafe.Pointer

	result := C.ursa_cl_non_credential_schema_builder_finalize(r.ptr, &nonSchema)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &NonCredentialSchemaHandle{nonSchema}, nil
}

// Free deallocates credential schema instance
func (r *NonCredentialSchemaHandle) Free() error {
	result := C.ursa_cl_non_credential_schema_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

type CredentialSchemaBuilder Handle
type CredentialSchemaHandle Handle

// NewCredentialSchemaBuilder creates and return credential schema entity builder
func NewCredentialSchemaBuilder() (*CredentialSchemaBuilder, error) {
	var builder unsafe.Pointer
	result := C.ursa_cl_credential_schema_builder_new(&builder)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialSchemaBuilder{builder}, nil
}

// AddAttr adds new attribute to credential schema
func (r *CredentialSchemaBuilder) AddAttr(field string) error {
	cfield := C.CString(field)
	result := C.ursa_cl_credential_schema_builder_add_attr(r.ptr, cfield)
	C.free(unsafe.Pointer(cfield))
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// Finalize deallocates credential schema builder and return credential schema entity instead
func (r *CredentialSchemaBuilder) Finalize() (*CredentialSchemaHandle, error) {
	var schema unsafe.Pointer

	result := C.ursa_cl_credential_schema_builder_finalize(r.ptr, &schema)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialSchemaHandle{schema}, nil
}

// Free deallocates credential schema instance
func (r *CredentialSchemaHandle) Free() error {
	result := C.ursa_cl_credential_schema_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

type CredentialDefPubKey Handle
type CredentialDefPrivKey Handle
type CredentialDefKeyCorrectnessProof Handle

// ToJSON creates and returns JSON representation of credential definition public key
func (r *CredentialDefPubKey) ToJSON() ([]byte, error) {
	var jsn *C.char

	result := C.ursa_cl_credential_public_key_to_json(r.ptr, &jsn)
	defer C.free(unsafe.Pointer(jsn))
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return []byte(C.GoString(jsn)), nil
}

// Free deallocates credential definition public key instance
func (r *CredentialDefPubKey) Free() error {
	result := C.ursa_cl_credential_public_key_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// ToJSON creates and returns JSON representation of credential definition private key
func (r *CredentialDefPrivKey) ToJSON() ([]byte, error) {
	var jsn *C.char

	result := C.ursa_cl_credential_private_key_to_json(r.ptr, &jsn)
	defer C.free(unsafe.Pointer(jsn))
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return []byte(C.GoString(jsn)), nil
}

// Free deallocates credential definition private key instance
func (r *CredentialDefPrivKey) Free() error {
	result := C.ursa_cl_credential_private_key_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// ToJSON creates and returns JSON representation of credential definition key correctness proof
func (r *CredentialDefKeyCorrectnessProof) ToJSON() ([]byte, error) {
	var jsn *C.char

	result := C.ursa_cl_credential_key_correctness_proof_to_json(r.ptr, &jsn)
	defer C.free(unsafe.Pointer(jsn))
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return []byte(C.GoString(jsn)), nil
}

// Free deallocates credential definition key correctness proof instance
func (r *CredentialDefKeyCorrectnessProof) Free() error {
	result := C.ursa_cl_credential_key_correctness_proof_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

type CredentialDef struct {
	PubKey              *CredentialDefPubKey
	PrivKey             *CredentialDefPrivKey
	KeyCorrectnessProof *CredentialDefKeyCorrectnessProof
}

// NewCredentialDef creates and returns credential definition (public and private keys, correctness proof) entities
func NewCredentialDef(schema *CredentialSchemaHandle, nonSchema *NonCredentialSchemaHandle, revocation bool) (*CredentialDef, error) {
	var credpub, credpriv, credproof unsafe.Pointer

	result := C.ursa_cl_issuer_new_credential_def(schema.ptr, nonSchema.ptr, C.bool(revocation), &credpub, &credpriv, &credproof)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	credDef := &CredentialDef{
		PubKey:              &CredentialDefPubKey{credpub},
		PrivKey:             &CredentialDefPrivKey{credpriv},
		KeyCorrectnessProof: &CredentialDefKeyCorrectnessProof{credproof},
	}

	return credDef, nil
}

// CorrectnessProofToJSON creates and returns JSON representation of credential signature correctness proof
func CorrectnessProofToJSON(credSignatureCorrectnessProof unsafe.Pointer) ([]byte, error) {
	var proofOut *C.char

	result := C.ursa_cl_signature_correctness_proof_to_json(credSignatureCorrectnessProof, &proofOut)
	defer C.free(unsafe.Pointer(proofOut))
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return []byte(C.GoString(proofOut)), nil
}

type SignatureParams struct {
	ProverID                                 string
	BlindedCredentialSecrets                 *BlindedCredentialSecretsHandle
	BlindedCredentialSecretsCorrectnessProof *BlindedCredentialSecretsCorrectnessProof
	CredentialIssuanceNonce                  *Nonce
	CredentialNonce                          *Nonce
	CredentialValues                         *CredentialValues
	CredentialPubKey                         *CredentialDefPubKey
	CredentialPrivKey                        *CredentialDefPrivKey
}

// NewSignatureParams creates an empty instance of SignatureParams
func NewSignatureParams() *SignatureParams {
	return &SignatureParams{}
}

type CredentialSignature Handle
type CredentialSignatureCorrectnessProof Handle

// CredentialSignatureFromJSON creates and returns credential signature from json
func CredentialSignatureFromJSON(jsn []byte) (*CredentialSignature, error) {
	var handle unsafe.Pointer
	cjson := C.CString(string(jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_credential_signature_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialSignature{handle}, nil
}

// CredentialSignatureCorrectnessProofFromJSON creates and returns credential signature correctness proof from json
func CredentialSignatureCorrectnessProofFromJSON(jsn []byte) (*CredentialSignatureCorrectnessProof, error) {
	var handle unsafe.Pointer
	cjson := C.CString(string(jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_signature_correctness_proof_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialSignatureCorrectnessProof{handle}, nil
}

// SignCredential signs credential values with primary keys only
func (r *SignatureParams) SignCredential() (*CredentialSignature, *CredentialSignatureCorrectnessProof, error) {
	var credSignature, credSignatureCorrectnessProof unsafe.Pointer

	did := C.CString(r.ProverID)

	result := C.ursa_cl_issuer_sign_credential(
		did,
		r.BlindedCredentialSecrets.ptr,
		r.BlindedCredentialSecretsCorrectnessProof.ptr,
		r.CredentialNonce.ptr,
		r.CredentialIssuanceNonce.ptr,
		r.CredentialValues.ptr,
		r.CredentialPubKey.ptr,
		r.CredentialPrivKey.ptr,
		&credSignature,
		&credSignatureCorrectnessProof)
	if result.code != 0 {
		return nil, nil, ursaError(C.GoString(result.message))
	}

	return &CredentialSignature{credSignature}, &CredentialSignatureCorrectnessProof{credSignatureCorrectnessProof}, nil
}

// ProcessCredentialSignature updates the credential signature by a credential secrets blinding factors.
func (r *CredentialSignature) ProcessCredentialSignature(values *CredentialValues, sigKP *CredentialSignatureCorrectnessProof,
	credentialSecretsBF *CredentialSecretsBlindingFactors, credPubKey *CredentialDefPubKey, issuanceNonce *Nonce) error {

	result := C.ursa_cl_prover_process_credential_signature(
		r.ptr,
		values.ptr,
		sigKP.ptr,
		credentialSecretsBF.ptr,
		credPubKey.ptr,
		issuanceNonce.ptr,
		nil, /* rev_key_pub */
		nil, /* rev_reg */
		nil, /* witness */
	)

	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}
	return nil
}

// Free deallocates credential signature instance
func (r *CredentialSignature) Free() error {
	result := C.ursa_cl_credential_signature_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// ToJSON creates and returns JSON representation of credential signature
func (r *CredentialSignature) ToJSON() ([]byte, error) {
	var jsn *C.char

	result := C.ursa_cl_credential_signature_to_json(r.ptr, &jsn)
	defer C.free(unsafe.Pointer(jsn))
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return []byte(C.GoString(jsn)), nil
}

// Free deallocates credential signature correctness proof instance
func (r *CredentialSignatureCorrectnessProof) Free() error {
	result := C.ursa_cl_signature_correctness_proof_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// ToJSON creates and returns JSON representation of credential signature correctness proof
func (r *CredentialSignatureCorrectnessProof) ToJSON() ([]byte, error) {
	var jsn *C.char

	result := C.ursa_cl_signature_correctness_proof_to_json(r.ptr, &jsn)
	defer C.free(unsafe.Pointer(jsn))
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return []byte(C.GoString(jsn)), nil
}

type BlindedCredentialSecretsHandle Handle
type CredentialSecretsBlindingFactors Handle
type BlindedCredentialSecretsCorrectnessProof Handle

// CredentialSecretsBlindingFactorsFromJSON creates and returns credential secrets blinding factors from json
func CredentialSecretsBlindingFactorsFromJSON(jsn []byte) (*CredentialSecretsBlindingFactors, error) {
	var handle unsafe.Pointer
	cjson := C.CString(string(jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_credential_secrets_blinding_factors_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialSecretsBlindingFactors{handle}, nil
}

// ToJSON creates and returns JSON representation of blinded credental secrets
func (r *BlindedCredentialSecretsHandle) ToJSON() ([]byte, error) {
	var jsn *C.char

	result := C.ursa_cl_blinded_credential_secrets_to_json(r.ptr, &jsn)
	defer C.free(unsafe.Pointer(jsn))
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return []byte(C.GoString(jsn)), nil
}

// Free deallocates blinded credential secrets instance
func (r *BlindedCredentialSecretsHandle) Free() error {
	result := C.ursa_cl_blinded_credential_secrets_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// ToJSON creates and returns JSON representation of credential secrets blinding factors
func (r *CredentialSecretsBlindingFactors) ToJSON() ([]byte, error) {
	var jsn *C.char

	result := C.ursa_cl_credential_secrets_blinding_factors_to_json(r.ptr, &jsn)
	defer C.free(unsafe.Pointer(jsn))
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return []byte(C.GoString(jsn)), nil
}

// Free deallocates credential secrets blinding factors instance
func (r *CredentialSecretsBlindingFactors) Free() error {
	result := C.ursa_cl_credential_secrets_blinding_factors_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// ToJSON creates and returns JSON representation of blinded credential secrets correctness proof
func (r *BlindedCredentialSecretsCorrectnessProof) ToJSON() ([]byte, error) {
	var jsn *C.char

	result := C.ursa_cl_blinded_credential_secrets_correctness_proof_to_json(r.ptr, &jsn)
	defer C.free(unsafe.Pointer(jsn))
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return []byte(C.GoString(jsn)), nil
}

// Free deallocates blinded credential secrets correctness proof instance
func (r *BlindedCredentialSecretsCorrectnessProof) Free() error {
	result := C.ursa_cl_blinded_credential_secrets_correctness_proof_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

type BlindedCredentialSecrets struct {
	Handle           *BlindedCredentialSecretsHandle
	BlindingFactor   *CredentialSecretsBlindingFactors
	CorrectnessProof *BlindedCredentialSecretsCorrectnessProof
}

// BlindCredentialSecrets creates blinded credential secrets for given issuer key and master secret
func BlindCredentialSecrets(credentialPubKey *CredentialDefPubKey, keyCorrectnessProof *CredentialDefKeyCorrectnessProof, nonce *Nonce,
	values *CredentialValues) (*BlindedCredentialSecrets, error) {

	var blindedCredentialSecrets, blindedCredentialSecretsCorrectnessProof, credentialSecretsBlindingFactors unsafe.Pointer

	result := C.ursa_cl_prover_blind_credential_secrets(
		credentialPubKey.ptr,
		keyCorrectnessProof.ptr,
		values.ptr,
		nonce.ptr,
		&blindedCredentialSecrets,
		&credentialSecretsBlindingFactors,
		&blindedCredentialSecretsCorrectnessProof)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &BlindedCredentialSecrets{
		Handle:           &BlindedCredentialSecretsHandle{blindedCredentialSecrets},
		BlindingFactor:   &CredentialSecretsBlindingFactors{credentialSecretsBlindingFactors},
		CorrectnessProof: &BlindedCredentialSecretsCorrectnessProof{blindedCredentialSecretsCorrectnessProof},
	}, nil

}

type UrsaError struct {
	Backtrace string
	Message   string
}

func ursaError(msg string) error {
	var cMsg *C.char
	defer C.free(unsafe.Pointer(cMsg))

	C.ursa_get_current_error(&cMsg)
	var ursaError UrsaError
	json.Unmarshal([]byte(C.GoString(cMsg)), &ursaError)

	return errors.Errorf("error from URSA: %s", ursaError.Message)
}
