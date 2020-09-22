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

struct ExternError ursa_cl_new_nonce(void** nonce_p);
struct ExternError ursa_cl_nonce_to_json(void* nonce, const char** nonce_json_p);
extern void ursa_get_current_error(const char** error_json_p);