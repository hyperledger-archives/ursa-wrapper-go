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

func ursaError(msg string) error {
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))

	C.ursa_get_current_error(&cMsg)
	return errors.Errorf("error from URSA: %s", C.GoString(cMsg))
}
