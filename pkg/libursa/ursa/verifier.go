package ursa

/*
   #cgo LDFLAGS: -lursa
   #include "ursa_cl.h"
   #include <stdlib.h>
*/
import "C"

import (
	"unsafe"
)

type ProofVerifier Handle

// NewProofVerifier creates and returns proof verifier.
func NewProofVerifier() (*ProofVerifier, error) {
	var verifier unsafe.Pointer

	result := C.ursa_cl_verifier_new_proof_verifier(&verifier)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &ProofVerifier{verifier}, nil
}

// Verify verifies proof and deallocates proof verifier.
func (r *ProofVerifier) Verify(proof *ProofHandle, nonce *Nonce) (bool, error) {
	var verified C.bool

	result := C.ursa_cl_proof_verifier_verify(r.ptr, proof.ptr, nonce.ptr, &verified)
	if result.code != 0 {
		return false, ursaError(C.GoString(result.message))
	}

	out := bool(verified)
	return out, nil
}

// AddCommonAttribute add a common attribute to the proof verifier
func (r *ProofVerifier) AddCommonAttribute(attr string) error {
	cattr := C.CString(attr)
	defer C.free(unsafe.Pointer(cattr))

	result := C.ursa_cl_proof_verifier_add_common_attribute(r.ptr, cattr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// AddSubProofRequest add a sub proof request to the proof verifier
func (r *ProofVerifier) AddSubProofRequest(subProof *SubProofRequestHandle, credSchema *CredentialSchemaHandle,
	nonCredSchema *NonCredentialSchemaHandle, pubKey *CredentialDefPubKey) error {

	result := C.ursa_cl_proof_verifier_add_sub_proof_request(r.ptr, subProof.ptr, credSchema.ptr, nonCredSchema.ptr,
		pubKey.ptr /*revoc_reg*/, nil /*witness*/, nil)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}
