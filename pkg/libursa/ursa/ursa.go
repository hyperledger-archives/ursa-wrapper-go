package ursa

/*
   #cgo LDFLAGS: -lursa
   #include "ursa_cl.h"
   #include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/pkg/errors"
)

//NewNonce creates a random nonce
func NewNonce() (string, error) {
	var nonce unsafe.Pointer
	defer C.free(nonce)

	result := C.ursa_cl_new_nonce(&nonce)
	if result.code != 0 {
		return "", ursaError(C.GoString(result.message))
	}
	defer C.ursa_cl_nonce_free(nonce)

	var d *C.char
	defer C.free(unsafe.Pointer(d))

	result = C.ursa_cl_nonce_to_json(nonce, &d)
	if result.code != 0 {
		return "", ursaError(C.GoString(result.message))
	}

	return C.GoString(d), nil
}

//NonceFromJson creates and returns nonce json
func NonceFromJson(jsn string) (unsafe.Pointer, error) {
	var handle unsafe.Pointer
	cjson := C.CString(fmt.Sprintf(`"%s"`, jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_nonce_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return handle, nil
}
// BlindedCredentialSecretsCorrectnessProofFromJSON creates and returns blinded credential secrets correctness proof json.
func BlindedCredentialSecretsCorrectnessProofFromJSON(jsn string) (unsafe.Pointer, error) {
	var handle unsafe.Pointer
	cjson := C.CString(jsn)
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_blinded_credential_secrets_correctness_proof_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return handle, nil
}


//CredentialKeyCorrectnessProofFromJSON creates and returns credential key correctness proof from json
func CredentialKeyCorrectnessProofFromJSON(jsn string) (unsafe.Pointer, error) {
	var handle unsafe.Pointer
	cjson := C.CString(jsn)
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_credential_key_correctness_proof_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return handle, nil
}

//BlindedCredentialSecretsFromJSON creates and returns blinded credential secrets from json
func BlindedCredentialSecretsFromJSON(jsn string) (unsafe.Pointer, error) {
	var handle unsafe.Pointer
	cjson := C.CString(jsn)
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_blinded_credential_secrets_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return handle, nil
}

//CredentialPrivateKeyFromJSON creates and returns credential private key from json
func CredentialPrivateKeyFromJSON(jsn string) (unsafe.Pointer, error) {
	var handle unsafe.Pointer
	cjson := C.CString(jsn)
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_credential_private_key_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return handle, nil
}

//CredentialPublicKeyFromJSON creates and returns credential public key from json
func CredentialPublicKeyFromJSON(jsn string) (unsafe.Pointer, error) {
	var handle unsafe.Pointer
	cjson := C.CString(jsn)
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_credential_public_key_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return handle, nil
}

func CredentialPublicKeyToJSON(pubKey unsafe.Pointer) ([]byte, error) {
	var pubJson *C.char
	result := C.ursa_cl_credential_public_key_to_json(pubKey, &pubJson)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}
	defer C.free(unsafe.Pointer(pubJson))

	return []byte(C.GoString(pubJson)), nil
}

//CredentialPrivateKeyToJSON returns json representation of credential private key
func CredentialPrivateKeyToJSON(privKey unsafe.Pointer) ([]byte, error) {
	var privJson *C.char
	result := C.ursa_cl_credential_private_key_to_json(privKey, &privJson)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}
	defer C.free(unsafe.Pointer(privJson))

	return []byte(C.GoString(privJson)), nil
}

//NonCredentialSchemaBuilderNew creates and returns non credential schema builder
func NonCredentialSchemaBuilderNew() (unsafe.Pointer, error) {
	var nonBuilder unsafe.Pointer

	result := C.ursa_cl_non_credential_schema_builder_new(&nonBuilder)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return nonBuilder, nil
}

//NonCredentialSchemaBuilderAddAttr adds new attribute to non credential schema
func NonCredentialSchemaBuilderAddAttr(nonBuilder unsafe.Pointer, attr string) error {
	cAttr := C.CString(attr)
	defer C.free(unsafe.Pointer(cAttr))

	result := C.ursa_cl_non_credential_schema_builder_add_attr(nonBuilder, cAttr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

//NonCredentialSchemaBuilderFinalize deallocates non_credential schema builder and returns non credential schema entity instead
func NonCredentialSchemaBuilderFinalize(nonBuilder unsafe.Pointer) (unsafe.Pointer, error) {
	var nonSchema unsafe.Pointer

	result := C.ursa_cl_non_credential_schema_builder_finalize(nonBuilder, &nonSchema)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return nonSchema, nil
}

//CredentialSchemaBuilderNew creates and return credential schema entity builder
func CredentialSchemaBuilderNew() (unsafe.Pointer, error) {
	var builder unsafe.Pointer
	result := C.ursa_cl_credential_schema_builder_new(&builder)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return builder, nil
}

//CredentialSchemaBuilderAddAttr adds new attribute to credential schema
func CredentialSchemaBuilderAddAttr(builder unsafe.Pointer, field string) error {
	cfield := C.CString(field)
	result := C.ursa_cl_credential_schema_builder_add_attr(builder, cfield)
	C.free(unsafe.Pointer(cfield))
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

//CredentialSchemaBuilderFinalize deallocates credential schema builder and return credential schema entity instead
func CredentialSchemaBuilderFinalize(builder unsafe.Pointer) (unsafe.Pointer, error) {
	var schema unsafe.Pointer

	result := C.ursa_cl_credential_schema_builder_finalize(builder, &schema)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return schema, nil
}

type CredentialDef struct {
	PubKey unsafe.Pointer
	PrivKey unsafe.Pointer
	KeyCorrectnessProof unsafe.Pointer
}

//NewCredentialDef creates and returns credential definition (public and private keys, correctness proof) entities
func NewCredentialDef(schema, nonSchema unsafe.Pointer, revocation bool) (*CredentialDef, error) {
	rev := C.bool(revocation)
	var credpub, credpriv, credproof unsafe.Pointer

	result := C.ursa_cl_issuer_new_credential_def(schema, nonSchema, rev, &credpub, &credpriv, &credproof)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	credDef := &CredentialDef{
		PubKey: credpub,
		PrivKey: credpriv,
		KeyCorrectnessProof: credproof,
	}

	return credDef, nil
}

//FreeCredentialSchema deallocates credential schema instance
func FreeCredentialSchema(schema unsafe.Pointer) error {
	result := C.ursa_cl_credential_schema_free(schema)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

//FreeNonCredentialSchema deallocates credential schema instance
func FreeNonCredentialSchema(nonSchema unsafe.Pointer) error {
	result := C.ursa_cl_non_credential_schema_free(nonSchema)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

//FreeCredentialPrivateKey deallocates credential private key instance
func FreeCredentialPrivateKey(privKey unsafe.Pointer) error {
	result := C.ursa_cl_credential_private_key_free(privKey)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

//FreeCredentialPublicKey deallocates credential public key instance
func FreeCredentialPublicKey(pubKey unsafe.Pointer) error {
	result := C.ursa_cl_credential_public_key_free(pubKey)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

//FreeCredentialKeyCorrectnessProof deallocates credential key correctness proof instance
func FreeCredentialKeyCorrectnessProof(proof unsafe.Pointer) error {
	result := C.ursa_cl_credential_key_correctness_proof_free(proof)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

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
	ProverID string
	BlindedCredentialSecrets string
	BlindedCredentialSecretsCorrectnessProof string
	CredentialIssuanceNonce string
	CredentialNonce string
	CredentialValues unsafe.Pointer
	CredentialPubKey string
	CredentialPrivKey string
}

//NewSignatureParams creates an empty instance of SignatureParams
func NewSignatureParams() *SignatureParams {
	return &SignatureParams{}
}

//SignCredential signs credential values with primary keys only
func (r *SignatureParams) SignCredential() (signature []byte, proof []byte, err error) {
	defer C.free(r.CredentialValues)
	var credSignature, credSignatureCorrectnessProof unsafe.Pointer

	did := C.CString(r.ProverID)

	blindedCredentialSecrets, err := BlindedCredentialSecretsFromJSON(r.BlindedCredentialSecrets)
	if err != nil {
		return nil, nil, err
	}

	blindedCredentialSecretsCorrectnessProof, err := BlindedCredentialSecretsCorrectnessProofFromJSON(r.BlindedCredentialSecretsCorrectnessProof)
	if err != nil {
		return nil, nil, err
	}

	credentialIssuanceNonce, err := NonceFromJson(r.CredentialIssuanceNonce)
	if err != nil {
		return nil, nil, err
	}

	credentialNonce, err := NonceFromJson(r.CredentialNonce)
	if err != nil {
		return nil, nil, err
	}

	credentialPubKey, err := CredentialPublicKeyFromJSON(r.CredentialPubKey)
	if err != nil {
		return nil, nil, err
	}

	credentialPrivKey, err := CredentialPrivateKeyFromJSON(r.CredentialPrivKey)
	if err != nil {
		return nil, nil, err
	}

	defer func() {
		C.free(unsafe.Pointer(did))
		C.free(blindedCredentialSecrets)
		C.free(blindedCredentialSecretsCorrectnessProof)
		C.free(credentialIssuanceNonce)
		C.free(credentialNonce)
		C.free(credentialPubKey)
		C.free(credentialPrivKey)
	}()

	result := C.ursa_cl_issuer_sign_credential(did, blindedCredentialSecrets, blindedCredentialSecretsCorrectnessProof,
		credentialIssuanceNonce, credentialNonce, r.CredentialValues, credentialPubKey, credentialPrivKey, &credSignature, &credSignatureCorrectnessProof)
	if result.code != 0 {
		return nil, nil, ursaError(C.GoString(result.message))
	}
	var sigOut *C.char
	result = C.ursa_cl_credential_signature_to_json(credSignature, &sigOut)
	if result.code != 0 {
		return nil, nil, ursaError(C.GoString(result.message))
	}
	defer C.free(unsafe.Pointer(sigOut))
	defer C.ursa_cl_credential_signature_free(credSignature)

	var proofOut *C.char
	result = C.ursa_cl_signature_correctness_proof_to_json(credSignatureCorrectnessProof, &proofOut)
	if result.code != 0 {
		return nil, nil, ursaError(C.GoString(result.message))
	}
	defer C.free(unsafe.Pointer(proofOut))

	return []byte(C.GoString(sigOut)), []byte(C.GoString(proofOut)), nil
}

func ursaError(msg string) error {
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))

	C.ursa_get_current_error(&cMsg)
	return errors.Errorf("error from URSA: %s", C.GoString(cMsg))
}
