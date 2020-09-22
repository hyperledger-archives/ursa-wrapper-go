package ursa

/*
   #cgo LDFLAGS: -lursa
   #include "ursa_cl.h"
   #include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

// NewNonce creates random nonce
func NewNonce() (string, error) {
	var nonce unsafe.Pointer
	defer C.free(nonce)

	var d *C.char
	defer C.free(unsafe.Pointer(d))

	result := C.ursa_cl_new_nonce(&nonce)
	if result.code != 0 {
		C.ursa_get_current_error(&result.message)
		return "", errors.New(C.GoString(result.message))
	}

	result = C.ursa_cl_nonce_to_json(nonce, &d)
	if result.code != 0 {
		return "", errors.New(C.GoString(result.message))
	}

	return C.GoString(d), nil
}
