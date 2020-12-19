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

type MasterSecret Handle

// NewMasterSecret creates a master secret
func NewMasterSecret() (*MasterSecret, error) {
	var ms unsafe.Pointer

	result := C.ursa_cl_prover_new_master_secret(&ms)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &MasterSecret{ms}, nil
}

//MasterSecretFromJson creates and returns master secret from json
func MasterSecretFromJSON(jsn []byte) (*MasterSecret, error) {
	var handle unsafe.Pointer
	cjson := C.CString(string(jsn))
	defer C.free(unsafe.Pointer(cjson))

	result := C.ursa_cl_master_secret_from_json(cjson, &handle)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &MasterSecret{handle}, nil
}

// ToJSON returns json representation of master secret
func (r *MasterSecret) ToJSON() ([]byte, error) {
	var d *C.char
	defer C.free(unsafe.Pointer(d))

	result := C.ursa_cl_master_secret_to_json(r.ptr, &d)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	out := []byte(C.GoString(d))
	return out, nil
}

// Free deallocates master secret instance
func (r *MasterSecret) Free() error {
	result := C.ursa_cl_master_secret_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}
