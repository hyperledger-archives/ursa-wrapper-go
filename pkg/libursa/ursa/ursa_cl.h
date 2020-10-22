#include <stdint.h>

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