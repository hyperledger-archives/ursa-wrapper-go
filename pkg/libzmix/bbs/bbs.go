package bbs

/*
   #cgo LDFLAGS: -lbbs
   #include "bbs_cl.h"
   #include <stdlib.h>
*/
import "C"
import (
	"unsafe"

	"github.com/pkg/errors"
)

type BlsKeyPair struct {
	PublicKey C.ByteBuffer
	SecretKey C.ByteBuffer
}

type HandleByteBuffer struct {
	Buffer C.ByteBuffer
}

func (r HandleByteBuffer) Free() {
	C.bbs_byte_buffer_free(r.Buffer)
}

//GenerateKey generates a bls key pair
func GenerateBlsKey(data []byte) (*BlsKeyPair, error) {
	var seed C.ByteBuffer
	defer C.bbs_byte_buffer_free(seed)
	var publicKey C.ByteBuffer
	var secretKey C.ByteBuffer
	var err C.ExternError

	seed.len = (C.long)(len(data))
	if len(data) > 0 {
		seed.data = (*C.uchar)(unsafe.Pointer(&data))
	}

	code := C.bls_generate_key(seed, &publicKey, &secretKey, &err)
	if code != 0 {
		return nil, errors.Errorf("err occurred generating BLS key pair: %s", C.GoString(err.message))
	}

	pkSize := C.bls_public_key_size()
	skSize := C.bls_secret_key_size()
	if publicKey.len != (C.long)(pkSize) || secretKey.len != (C.long)(skSize) {
		return nil, errors.Errorf("key pair lengths are invalid")
	}

	return &BlsKeyPair{
		PublicKey: publicKey,
		SecretKey: secretKey,
	}, nil
}

//FreeSecretKey deallocates the secret key instance
func (r *BlsKeyPair) FreeSecretKey() {
	C.bbs_byte_buffer_free(r.SecretKey)
}

//FreeSecretKey deallocates the public key instance
func (r *BlsKeyPair) FreePublicKey() {
	C.bbs_byte_buffer_free(r.PublicKey)
}

//BlsPublicKeyToBBSKey converts a bls public key to a BBS public key
func (r *BlsKeyPair) BlsPublicKeyToBBSKey(messageCount int) (*HandleByteBuffer, error) {
	var bbsPublicKey C.ByteBuffer
	var err C.ExternError

	count := (C.uint)(messageCount)

	code := C.bls_public_key_to_bbs_key(r.PublicKey, count, &bbsPublicKey, &err)
	if code != 0 {
		return nil, errors.Errorf("error occurred converting BLS public key to BBS public key: %s", C.GoString(err.message))
	}

	return &HandleByteBuffer{Buffer: bbsPublicKey}, nil
}

type Handle struct {
	data C.ulong
}

type BlindSignContext Handle

//BlindSignContext initializes a blind sign context
func BlindSignContextInit() (*BlindSignContext, error) {
	var err C.ExternError

	handle := C.bbs_blind_sign_context_init(&err)
	if err.code != 0 {
		return nil, errors.Errorf("error occurred initializing BBS sign context: %s", C.GoString(err.message))
	}

	return &BlindSignContext{handle}, nil
}

//SetPublicKey sets the bbs public key on the BlindSignContext
func (r *BlindSignContext) SetPublicKey(publicKey HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_blind_sign_context_set_public_key(r.data, publicKey.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting secret key to BBS sign context: %s", C.GoString(err.message))
	}

	return nil
}

//SetSecretKey sets the bls secret key on the BlindSignContext
func (r *BlindSignContext) SetSecretKey(secretKey HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_blind_sign_context_set_secret_key(r.data, secretKey.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting secret key to BBS sign context: %s", C.GoString(err.message))
	}

	return nil
}

//SetCommitment sets the commitment on the BlindSignContext
func (r *BlindSignContext) SetCommitment(blindCommitment HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_blind_sign_context_set_commitment(r.data, blindCommitment.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting blind commitment to BBS blind sign context: %s", C.GoString(err.message))
	}

	return nil
}

//AddMessage adds the message and associated index to BlindSignContext
func (r *BlindSignContext) AddMessage(message string, index int) error {
	var err C.ExternError
	var cMessage C.ByteBuffer

	cm := C.CString(message)
	cMessage.len = (C.long)(len(message))
	cMessage.data = (*C.uchar)(unsafe.Pointer(cm))
	code := C.bbs_blind_sign_context_add_message_bytes(r.data, (C.uint)(index), cMessage, &err)
	if code != 0 {
		return errors.Errorf("error occurred adding message bytes to BBS sign context: %s", C.GoString(err.message))
	}

	return nil
}

type BlindedSignature HandleByteBuffer

//Finish generates a BlindedSignature from a BlindSignContext
func (r *BlindSignContext) Finish() (*BlindedSignature, error) {
	var err C.ExternError
	var blindedSignature C.ByteBuffer

	code := C.bbs_blind_sign_context_finish(r.data, &blindedSignature, &err)
	if code != 0 {
		return nil, errors.Errorf("error occurred finishing BBS sign context: %s", C.GoString(err.message))
	}

	sigSize := C.bbs_blind_signature_size()
	if blindedSignature.len != (C.long)(sigSize) {
		return nil, errors.Errorf("signature is incorrect size")
	}

	return &BlindedSignature{Buffer: blindedSignature}, nil
}

//Unblind returns the Signature from the BlindedSignature
func (r *BlindedSignature) Unblind(blindingFactor HandleByteBuffer) (*Signature, error) {
	var unblindSignature C.ByteBuffer
	var err C.ExternError

	code := C.bbs_unblind_signature(r.Buffer, blindingFactor.Buffer, &unblindSignature, &err)
	if code != 0 {
		return nil, errors.Errorf("error occurred unblinding signature: %s", C.GoString(err.message))
	}

	sigSize := C.bbs_signature_size()
	if unblindSignature.len != (C.long)(sigSize) {
		return nil, errors.Errorf("signature is incorrect size")
	}

	return &Signature{unblindSignature}, nil
}

type SignContext Handle

//SignContextInit initializes a sign context
func SignContextInit() (*SignContext, error) {
	var err C.ExternError

	handle := C.bbs_sign_context_init(&err)
	if err.code != 0 {
		return nil, errors.Errorf("error occurred initializing BBS sign context: %s", C.GoString(err.message))
	}

	return &SignContext{handle}, nil
}

//SetPublicKey sets the public key on the SignContext
func (r *SignContext) SetPublicKey(publicKey HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_sign_context_set_public_key(r.data, publicKey.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting secret key to BBS sign context: %s", C.GoString(err.message))
	}

	return nil
}

//SetSecretKey sets the bls secret key on teh SignContext
func (r *SignContext) SetSecretKey(secretKey HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_sign_context_set_secret_key(r.data, secretKey.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting secret key to BBS sign context: %s", C.GoString(err.message))
	}

	return nil
}

//AddMessages adds messages to the SignContext
func (r *SignContext) AddMessages(messages []string) error {
	var err C.ExternError
	var message C.ByteBuffer
	defer C.bbs_byte_buffer_free(message)

	for _, m := range messages {
		message.len = (C.long)(len(m))
		cm := C.CString(m)
		message.data = (*C.uchar)(unsafe.Pointer(&cm))
		code := C.bbs_sign_context_add_message_bytes(r.data, message, &err)
		if code != 0 {
			return errors.Errorf("error occurred adding message bytes to BBS sign context: %s", C.GoString(err.message))
		}
	}

	return nil
}

type Signature HandleByteBuffer

//Finish generates a Signature from the SignContext
func (r *SignContext) Finish() (*Signature, error) {
	var err C.ExternError
	var signature C.ByteBuffer

	code := C.bbs_sign_context_finish(r.data, &signature, &err)
	if code != 0 {
		return nil, errors.Errorf("error occurred finishing BBS sign context: %s", C.GoString(err.message))
	}

	sigSize := C.bbs_signature_size()
	if signature.len != (C.long)(sigSize) {
		return nil, errors.Errorf("signature is incorrect size")
	}

	return &Signature{Buffer: signature}, nil
}

//Free deallocates the Signature instance
func (r *Signature) Free() {
	C.bbs_byte_buffer_free(r.Buffer)
}

type BlindCommitmentContext Handle

//BlindCommitmentContextInit initializes a BlindCommitmentContext
func BlindCommitmentContextInit() (*BlindCommitmentContext, error) {
	var err C.ExternError

	handle := C.bbs_blind_commitment_context_init(&err)
	if err.code != 0 {
		return nil, errors.Errorf("error occurred initializing BBS blind commitment context: %s", C.GoString(err.message))
	}

	return &BlindCommitmentContext{handle}, nil
}

//SetPublicKey sets the bbs public key on the BlindCommitmentContext
func (r *BlindCommitmentContext) SetPublicKey(publicKey HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_blind_commitment_context_set_public_key(r.data, publicKey.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting secret key to BBS sign context: %s", C.GoString(err.message))
	}

	return nil
}

//AddMessage adds a message and its associated index to the BlindCommitmentContext
func (r *BlindCommitmentContext) AddMessage(message string, index int) error {
	var err C.ExternError
	var cMessage C.ByteBuffer
	defer C.bbs_byte_buffer_free(cMessage)

	cMessage.len = (C.long)(len(message))
	cm := C.CString(message)
	cMessage.data = (*C.uchar)(unsafe.Pointer(cm))
	code := C.bbs_blind_commitment_context_add_message_bytes(r.data, (C.uint)(index), cMessage, &err)
	if code != 0 {
		return errors.Errorf("error occurred adding message bytes to BBS blind commitment context: %s", C.GoString(err.message))
	}

	return nil
}

//SetNonce sets the nonce on the BlindedCommitmentContext
func (r *BlindCommitmentContext) SetNonce(nonce []byte) error {
	var err C.ExternError
	var nonceBuffer C.ByteBuffer
	defer C.bbs_byte_buffer_free(nonceBuffer)

	nonceBuffer.len = (C.long)(len(nonce))
	nonceBuffer.data = (*C.uchar)(unsafe.Pointer(&nonce))

	code := C.bbs_blind_commitment_context_set_nonce_bytes(r.data, nonceBuffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting nonce bytes on BBS blind commitment context: %s", C.GoString(err.message))
	}

	return nil
}

type BlindedCommitment struct {
	Commitment     C.ByteBuffer
	Context        C.ByteBuffer
	BlindingFactor C.ByteBuffer
}

//Finish generates a commitment, context, and blinding factor from the BlindCommitmentContext
func (r *BlindCommitmentContext) Finish() (*BlindedCommitment, error) {
	var err C.ExternError
	var commitment C.ByteBuffer
	var outContext C.ByteBuffer
	var blindingFactor C.ByteBuffer

	code := C.bbs_blind_commitment_context_finish(r.data, &commitment, &outContext, &blindingFactor, &err)
	if code > 0 {
		return nil, errors.Errorf("error occurred finishing BBS sign context: %s", C.GoString(err.message))
	}

	return &BlindedCommitment{
		Commitment:     commitment,
		Context:        outContext,
		BlindingFactor: blindingFactor,
	}, nil
}

//FreeCommitment deallocates the Commitment, Context, and BlindingFactor instances from the BlindedCommitment
func (r *BlindedCommitment) Free() {
	C.bbs_byte_buffer_free(r.Commitment)
	C.bbs_byte_buffer_free(r.Context)
	C.bbs_byte_buffer_free(r.BlindingFactor)
}

type VerifyBlindCommitmentContext Handle

//VerifyBlindCommitmentContextInit initializes a VerifyBlindCommitmentContext
func VerifyBlindCommitmentContextInit() (*VerifyBlindCommitmentContext, error) {
	var err C.ExternError

	handle := C.bbs_verify_blind_commitment_context_init(&err)
	if err.code != 0 {
		return nil, errors.Errorf("error occurred initializing BBS verify blinded commitment context: %s", C.GoString(err.message))
	}

	return &VerifyBlindCommitmentContext{data: handle}, nil
}

//SetPublicKey sets the bbs public key on the VerifyBlindCommitmentContext
func (r *VerifyBlindCommitmentContext) SetPublicKey(publicKey HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_verify_blind_commitment_context_set_public_key(r.data, publicKey.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting secret key to BBS sign context: %s", C.GoString(err.message))
	}

	return nil
}

//SetNonce sets the nonce on the VerifyBlindCommitmentContext
func (r *VerifyBlindCommitmentContext) SetNonce(nonce []byte) error {
	var err C.ExternError
	var nonceBuffer C.ByteBuffer
	defer C.bbs_byte_buffer_free(nonceBuffer)

	nonceBuffer.len = (C.long)(len(nonce))
	nonceBuffer.data = (*C.uchar)(unsafe.Pointer(&nonce))

	code := C.bbs_verify_blind_commitment_context_set_nonce_bytes(r.data, nonceBuffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting nonce bytes on BBS verify blind commitment context: %s", C.GoString(err.message))
	}

	return nil
}

//AddBlinded adds the index of the blinded message to the VerifyBlindCommitmentContext
func (r *VerifyBlindCommitmentContext) AddBlinded(index int) error {
	var err C.ExternError

	code := C.bbs_verify_blind_commitment_context_add_blinded(r.data, (C.uint)(index), &err)
	if code != 0 {
		return errors.Errorf("error occurred setting blinded index on BBS verify blind commitment context: %s", C.GoString(err.message))
	}

	return nil
}

//SetProof sets the context from the BlindCommitmentContext on the VerifyBlindCommitmentContext
func (r *VerifyBlindCommitmentContext) SetProof(proof HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_verify_blind_commitment_context_set_proof(r.data, proof.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting proof on BBS verify blind commitment context: %s", C.GoString(err.message))
	}

	return nil
}

//Finish verifies the BlindCommitmentContext
func (r *VerifyBlindCommitmentContext) Finish() error {
	var err C.ExternError

	code := C.bbs_verify_blind_commitment_context_finish(r.data, &err)
	if err.code != 0 {
		return errors.Errorf("error occurred finishing BBS verify proof context: %s", C.GoString(err.message))
	}

	if code != 200 {
		if ProofStatus[code] != "" {
			return errors.Errorf("failed to verify proof: %s", ProofStatus[code])
		}
		return errors.Errorf("unknown error occurred verifying proof: %d", code)
	}

	return nil
}

type VerifyContext Handle

//VerifyContextInit initializes a VerifyContext
func VerifyContextInit() (*VerifyContext, error) {
	var err C.ExternError

	handle := C.bbs_verify_context_init(&err)
	if err.code != 0 {
		return nil, errors.Errorf("error occurred initializing BBS verify context: %s", C.GoString(err.message))
	}

	return &VerifyContext{data: handle}, nil
}

//AddMessages adds the messages to the VerifyContext
func (r *VerifyContext) AddMessages(messages []string) error {
	var err C.ExternError
	var message C.ByteBuffer

	for _, m := range messages {
		message.len = (C.long)(len(m))
		cm := C.CString(m)
		message.data = (*C.uchar)(unsafe.Pointer(cm))
		code := C.bbs_verify_context_add_message_bytes(r.data, message, &err)
		if code != 0 {
			return errors.Errorf("error occurred adding message bytes to BBS verify context: %s", C.GoString(err.message))
		}
	}

	return nil
}

//SetPublicKey sets the bbs public key on the VerifyContext
func (r *VerifyContext) SetPublicKey(publicKey HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_verify_context_set_public_key(r.data, publicKey.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting secret key to BBS verify context: %s", C.GoString(err.message))
	}

	return nil
}

//SetSignature sets the signature on the VerifyContext
func (r *VerifyContext) SetSignature(signature *Signature) error {
	var err C.ExternError

	code := C.bbs_verify_context_set_signature(r.data, signature.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting signature to BBS verify context: %s", C.GoString(err.message))
	}

	return nil
}

//Finish verifies a BBS+ signature for a set of messages with a BBS public key
func (r *VerifyContext) Finish() (bool, error) {
	var err C.ExternError
	code := C.bbs_verify_context_finish(r.data, &err)
	if err.code != 0 {
		return code == 0, errors.Errorf("error occurred finishing VerifyContext: %s", C.GoString(err.message))
	}
	return code == 0, nil
}

type ProofContext Handle

//ProofContextInit creates the proof asynchronous
func ProofContextInit() (*ProofContext, error) {
	var err C.ExternError

	handle := C.bbs_create_proof_context_init(&err)
	if err.code != 0 {
		return nil, errors.Errorf("error occurred initializing BBS create proof context: %s", C.GoString(err.message))
	}

	return &ProofContext{data: handle}, nil
}

type ProofMessageType int

const (
	Revealed                    ProofMessageType = 1
	HiddenProofSpecificBlinding ProofMessageType = 2
	HiddenExternalBlinding      ProofMessageType = 3
)

//AddProofMessage adds a proof message to the proof context
func (r *ProofContext) AddProofMessages(messages []string, messageType ProofMessageType, blindingFactor HandleByteBuffer) error {
	var err C.ExternError
	var proofMessageType C.proof_message_t

	switch messageType {
	case 1:
		proofMessageType = C.Revealed
	case 2:
		proofMessageType = C.HiddenProofSpecificBlinding
	case 3:
		proofMessageType = C.HiddenExternalBlinding
	}

	for _, m := range messages {
		var message C.ByteBuffer
		message.len = (C.long)(len(m))
		cm := C.CString(m)
		message.data = (*C.uchar)(unsafe.Pointer(cm))
		code := C.bbs_create_proof_context_add_proof_message_bytes(r.data, message, proofMessageType, blindingFactor.Buffer, &err)
		if code != 0 {
			return errors.Errorf("error occurred adding message bytes to BBS create proof context: %s", C.GoString(err.message))
		}
	}

	return nil
}

//SetSignature sets the signature on the ProofContext
func (r *ProofContext) SetSignature(signature *Signature) error {
	var err C.ExternError

	code := C.bbs_create_proof_context_set_signature(r.data, signature.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting signature to BBS create proof context: %s", C.GoString(err.message))
	}

	return nil
}

//SetPublicKey sets the bbs public key on the ProofContext
func (r *ProofContext) SetPublicKey(publicKey HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_create_proof_context_set_public_key(r.data, publicKey.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting secret key to BBS create proof context: %s", C.GoString(err.message))
	}

	return nil
}

//SetNonce sets the nonce on the ProofContext
func (r *ProofContext) SetNonce(nonce []byte) error {
	var err C.ExternError
	var nonceBuffer C.ByteBuffer

	nonceBuffer.len = (C.long)(len(nonce))
	nonceBuffer.data = (*C.uchar)(unsafe.Pointer(&nonce))

	code := C.bbs_create_proof_context_set_nonce_bytes(r.data, nonceBuffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting nonce bytes on BBS create proof context: %s", C.GoString(err.message))
	}

	return nil
}

type Proof HandleByteBuffer

//Finish generates a proof from the ProofContext
func (r *ProofContext) Finish() (*Proof, error) {
	var proof C.ByteBuffer
	var err C.ExternError

	code := C.bbs_create_proof_context_finish(r.data, &proof, &err)
	if code != 0 {
		return nil, errors.Errorf("error occurred finishing BBS create proof context: %s", C.GoString(err.message))
	}

	return &Proof{Buffer: proof}, nil
}

//Free deallocates the proof instance
func (r *Proof) Free() {
	C.bbs_byte_buffer_free(r.Buffer)
}

type VerifyProofContext Handle

//VerifyProofContextInit initializes a VerifyProofContext
func VerifyProofContextInit() (*VerifyProofContext, error) {
	var err C.ExternError

	handle := C.bbs_verify_proof_context_init(&err)
	if err.code != 0 {
		return nil, errors.Errorf("error occurred initializing BBS verify proof context: %s", C.GoString(err.message))
	}

	return &VerifyProofContext{data: handle}, nil
}

//AddMessages adds the message and the associated index to the VerifyProofContext
func (r *VerifyProofContext) AddMessage(message string, index int) error {
	var err C.ExternError
	var cMessage C.ByteBuffer

	cMessage.len = (C.long)(len(message))
	cm := C.CString(message)
	cMessage.data = (*C.uchar)(unsafe.Pointer(cm))
	code := C.bbs_verify_proof_context_add_message_bytes(r.data, (C.uint)(index), cMessage, &err)
	if code != 0 {
		return errors.Errorf("error occurred adding message bytes to BBS verify proof context: %s", C.GoString(err.message))
	}

	return nil
}

//SetProof sets the proof on the VerifyProofContext
func (r *VerifyProofContext) SetProof(proof HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_verify_proof_context_set_proof(r.data, proof.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting proof to BBS verify proof context: %s", C.GoString(err.message))
	}

	return nil
}

//SetPublicKey sets the bbs public key on the VerifyProofContext
func (r *VerifyProofContext) SetPublicKey(publicKey HandleByteBuffer) error {
	var err C.ExternError

	code := C.bbs_verify_proof_context_set_public_key(r.data, publicKey.Buffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting secret key to BBS create proof context: %s", C.GoString(err.message))
	}

	return nil
}

//SetNonce sets the nonce on the VerifyProofContext
func (r *VerifyProofContext) SetNonce(nonce []byte) error {
	var err C.ExternError
	var nonceBuffer C.ByteBuffer

	nonceBuffer.len = (C.long)(len(nonce))
	nonceBuffer.data = (*C.uchar)(unsafe.Pointer(&nonce))

	code := C.bbs_verify_proof_context_set_nonce_bytes(r.data, nonceBuffer, &err)
	if code != 0 {
		return errors.Errorf("error occurred setting nonce bytes on BBS create proof context: %s", C.GoString(err.message))
	}

	return nil
}

//Finish verifies a proof
func (r *VerifyProofContext) Finish() error {
	var err C.ExternError

	code := C.bbs_verify_proof_context_finish(r.data, &err)
	if err.code != 0 {
		return errors.Errorf("error occurred finishing BBS verify proof context: %s", C.GoString(err.message))
	}

	if code != 200 {
		if ProofStatus[code] != "" {
			return errors.Errorf("failed to verify proof: %s", ProofStatus[code])
		}
		return errors.Errorf("unknown error occurred verifying proof: %d", code)
	}

	return nil
}

var ProofStatus = map[C.int]string{
	400: "The proof failed because the signature proof of knowledge failed",
	401: "The proof failed because a hidden message was invalid when the proof was created",
	402: "The proof failed because a revealed message was invalid",
}
