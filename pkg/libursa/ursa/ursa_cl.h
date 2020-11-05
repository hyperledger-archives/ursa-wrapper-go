#include <stdint.h>
#include <stdbool.h>

typedef enum {
    Success = 0,
    CommonInvalidParam1 = 100,
    CommonInvalidParam2 = 101,
    CommonInvalidParam3 = 102,
    CommonInvalidParam4 = 103,
    CommonInvalidParam5 = 104,
    CommonInvalidParam6 = 105,
    CommonInvalidParam7 = 106,
    CommonInvalidParam8 = 107,
    CommonInvalidParam9 = 108,
    CommonInvalidParam10 = 109,
    CommonInvalidParam11 = 110,
    CommonInvalidParam12 = 111,
    CommonInvalidState = 112,
    CommonInvalidStructure = 113,
    CommonIOError = 114,
    AnoncredsRevocationAccumulatorIsFull = 115,
    AnoncredsInvalidRevocationAccumulatorIndex = 116,
    AnoncredsCredentialRevoked = 117,
    AnoncredsProofRejected = 118,
} ursa_error_t;

struct ExternError {
    ursa_error_t code;
    char* message; /* note: nullable */
};

typedef uintptr_t ErrorCode;

//mod

/**
 * Get details for last occurred error.
 *
 * NOTE: Error is stored until the next one occurs.
 *       Returning pointer has the same lifetime.
 *
 * #Params
 * * `error_json_p` - Reference that will contain error details (if any error has occurred before)
 *  in the format:
 * {
 *     "backtrace": Optional<str> - error backtrace.
 *         Collecting of backtrace can be enabled by setting environment variable `RUST_BACKTRACE=1`
 *     "message": str - human-readable error description
 * }
 *
 */
extern void ursa_get_current_error(const char** error_json_p);

/**
 * Creates random nonce.
 *
 * Note that nonce deallocation must be performed by calling ursa_cl_nonce_free.
 *
 * # Arguments
 * * `nonce_p` - Reference that will contain nonce instance pointer.
 */
struct ExternError ursa_cl_new_nonce(void** nonce_p);

/**
 * Returns json representation of nonce.
 *
 * # Arguments
 * * `nonce` - Reference that contains nonce instance pointer.
 * * `nonce_json_p` - Reference that will contain nonce json.
 */
struct ExternError ursa_cl_nonce_to_json(void* nonce, const char** nonce_json_p);

/**
 * Deallocates nonce instance.
 *
 * # Arguments
 * * `nonce` - Reference that contains nonce instance pointer.
 */
ErrorCode ursa_cl_nonce_free(const void *nonce);


/**
 * Creates and returns nonce json.
 *
 * Note: Nonce instance deallocation must be performed by calling ursa_cl_nonce_free.
 *
 * # Arguments
 * * `nonce_json` - Reference that contains nonce json.
 * * `nonce_p` - Reference that will contain nonce instance pointer.
 */
struct ExternError ursa_cl_nonce_from_json(const char *nonce_json, const void **nonce_p);

/**
 * Creates and returns credential key correctness proof from json.
 *
 * Note: Credential key correctness proof instance deallocation must be performed
 * by calling ursa_cl_credential_key_correctness_proof_free
 *
 * # Arguments
 * * `credential_key_correctness_proof_json` - Reference that contains credential key correctness proof json.
 * * `credential_key_correctness_proof_p` - Reference that will contain credential key correctness proof instance pointer.
 */
struct ExternError ursa_cl_credential_key_correctness_proof_from_json(const char *credential_key_correctness_proof_json,
                                                             const void **credential_key_correctness_proof_p);

/**
 * Creates and returns blinded credential secrets correctness proof json.
 *
 * Note: Blinded credential secrets correctness proof instance deallocation must be performed
 * by calling ursa_cl_blinded_credential_secrets_correctness_proof_free.
 *
 * # Arguments
 * * `blinded_credential_secrets_correctness_proof_json` - Reference that contains blinded credential secrets correctness proof json.
 * * `blinded_credential_secrets_correctness_proof_p` - Reference that will contain blinded credential secret correctness proof instance pointer.
 */
struct ExternError ursa_cl_blinded_credential_secrets_correctness_proof_from_json(const char *blinded_credential_secrets_correctness_proof_json,
                                                                         const void **blinded_credential_secrets_correctness_proof_p);

/**
 * Creates and returns blinded credential secrets from json.
 *
 * Note: Blinded credential secrets instance deallocation must be performed
 * by calling ursa_cl_blinded_credential_secrets_free
 *
 * # Arguments
 * * `blinded_credential_secrets_json` - Reference that contains blinded credential secret json.
 * * `blinded_credential_secrets_p` - Reference that will contain blinded credential secret instance pointer.
 */
struct ExternError ursa_cl_blinded_credential_secrets_from_json(const char *blinded_credential_secrets_json,
                                                       const void **blinded_credential_secrets_p);

/**
* Creates and returns credential private key from json.
*
* Note: Credential private key instance deallocation must be performed
* by calling ursa_cl_credential_private_key_free
*
* # Arguments
* * `credential_priv_key_json` - Reference that contains credential private key json.
* * `credential_priv_key_p` - Reference that will contain credential private key instance pointer.
*/
struct ExternError ursa_cl_credential_private_key_from_json(const char *credential_priv_key_json,
                                                  const void **credential_priv_key_p);

/**
 * Creates and returns credential public key from json.
 *
 * Note: Credential public key instance deallocation must be performed
 * by calling ursa_cl_credential_public_key_free
 *
 * # Arguments
 * * `credential_pub_key_json` - Reference that contains credential public key json.
 * * `credential_pub_key_p` - Reference that will contain credential public key instance pointer.
 */
struct ExternError ursa_cl_credential_public_key_from_json(const char *credential_pub_key_json,
                                                  const void **credential_pub_key_p);
/**
 * Returns json representation of credential signature.
 *
 * # Arguments
 * * `credential_signature` - Reference that contains credential signature pointer.
 * * `credential_signature_json_p` - Reference that will contain credential signature json.
 */
struct ExternError ursa_cl_credential_signature_to_json(const void *credential_signature,
                                               const char **credential_signature_json_p);

/**
 * Signs credential values with primary keys only.
 *
 * Note that credential signature instances deallocation must be performed by
 * calling ursa_cl_credential_signature_free.
 *
 * Note that credential signature correctness proof instances deallocation must be performed by
 * calling ursa_cl_signature_correctness_proof_free.
 *
 * # Arguments
 * * `prover_id` - Prover identifier.
 * * `blinded_credential_secrets` - Blinded master secret instance pointer generated by Prover.
 * * `blinded_credential_secrets_correctness_proof` - Blinded master secret correctness proof instance pointer.
 * * `credential_nonce` - Nonce instance pointer used for verification of blinded_credential_secrets_correctness_proof.
 * * `credential_issuance_nonce` - Nonce instance pointer used for creation of signature_correctness_proof.
 * * `credential_values` - Credential values to be signed instance pointer.
 * * `credential_pub_key` - Credential public key instance pointer.
 * * `credential_priv_key` - Credential private key instance pointer.
 * * `credential_signature_p` - Reference that will contain credential signature instance pointer.
 * * `credential_signature_correctness_proof_p` - Reference that will contain credential signature correctness proof instance pointer.
 */
struct ExternError ursa_cl_issuer_sign_credential(const char *prover_id,
                                         const void *blinded_credential_secrets,
                                         const void *blinded_credential_secrets_correctness_proof,
                                         const void *credential_nonce,
                                         const void *credential_issuance_nonce,
                                         const void *credential_values,
                                         const void *credential_pub_key,
                                         const void *credential_priv_key,
                                         const void **credential_signature_p,
                                         const void **credential_signature_correctness_proof_p);

/**
 * Returns json representation of signature correctness proof.
 *
 * # Arguments
 * * `signature_correctness_proof` - Reference that contains signature correctness proof instance pointer.
 * * `signature_correctness_proof_json_p` - Reference that will contain signature correctness proof json.
 */
struct ExternError ursa_cl_signature_correctness_proof_to_json(const void *signature_correctness_proof,
                                                      const char **signature_correctness_proof_json_p);

/**
 * Deallocates credential signature signature instance.
 *
 * # Arguments
 * * `credential_signature` - Reference that contains credential signature instance pointer.
 */
struct ExternError ursa_cl_credential_signature_free(const void *credential_signature);

/**
 * Creates and returns credential definition (public and private keys, correctness proof) entities.
 *
 * Note that credential public key instances deallocation must be performed by
 * calling ursa_cl_credential_public_key_free.
 *
 * Note that credential private key instances deallocation must be performed by
 * calling ursa_cl_credential_private_key_free.
 *
 * Note that credential key correctness proof instances deallocation must be performed by
 * calling ursa_cl_credential_key_correctness_proof_free.
 *
 * # Arguments
 * * `credential_schema` - Reference that contains credential schema instance pointer.
 * * `non_credential_schema` - Reference that contains non credential schema instance pointer
 * * `support_revocation` - If true non revocation part of credential keys will be generated.
 * * `credential_pub_key_p` - Reference that will contain credential public key instance pointer.
 * * `credential_priv_key_p` - Reference that will contain credential private key instance pointer.
 * * `credential_key_correctness_proof_p` - Reference that will contain credential keys correctness proof instance pointer.
 */
struct ExternError ursa_cl_issuer_new_credential_def(const void *credential_schema,
                                            const void *non_credential_schema,
                                            _Bool support_revocation,
                                            const void **credential_pub_key_p,
                                            const void **credential_priv_key_p,
                                            const void **credential_key_correctness_proof_p);

/**
 * Deallocates credential schema instance.
 *
 * # Arguments
 * * `credential_schema` - Reference that contains credential schema instance pointer.
 */
struct ExternError ursa_cl_credential_schema_free(const void *credential_schema);

/**
 * Deallocates credential key correctness proof instance.
 *
 * # Arguments
 * * `credential_key_correctness_proof` - Reference that contains credential key correctness proof instance pointer.
 */
struct ExternError ursa_cl_credential_key_correctness_proof_free(const void *credential_key_correctness_proof);

/**
 * Deallocates credential schema instance.
 *
 * # Arguments
 * * `non_credential_schema` - Reference that contains non credential schema instance pointer.
 */
struct ExternError ursa_cl_non_credential_schema_free(const void *non_credential_schema);

/**
 * Deallocates credential private key instance.
 *
 * # Arguments
 * * `credential_priv_key` - Reference that contains credential private key instance pointer.
 */
struct ExternError ursa_cl_credential_private_key_free(const void *credential_priv_key);

/**
 * Deallocates credential public key instance.
 *
 * # Arguments
 * * `credential_pub_key` - Reference that contains credential public key instance pointer.
 */
struct ExternError ursa_cl_credential_public_key_free(const void *credential_pub_key);