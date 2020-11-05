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

// NewValuesBuilder creates and returns credentials values entity builder
func NewValueBuilder() (unsafe.Pointer, error) {
	var builder unsafe.Pointer

	result := C.ursa_cl_credential_values_builder_new(&builder)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return builder, nil
}

// AddDecHidden adds new hidden attribute dec_value to credential values map
func AddDecHidden(builder unsafe.Pointer, attr, decValue string) error {
	cattr := C.CString(attr)
	defer C.free(unsafe.Pointer(cattr))

	cval := C.CString(decValue)
	defer C.free(unsafe.Pointer(cval))

	result := C.ursa_cl_credential_values_builder_add_dec_hidden(builder, cattr, cval)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// AddDecKnown adds new known attribute dec_value to credential values map
func AddDecKnown(builder unsafe.Pointer, attr, decValue string) error {
	cattr := C.CString(attr)
	defer C.free(unsafe.Pointer(cattr))
	cval := C.CString(decValue)
	defer C.free(unsafe.Pointer(cval))

	result := C.ursa_cl_credential_values_builder_add_dec_known(builder, cattr, cval)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// AddDecCommitment adds new hidden attribute dec_value to credential values map
func AddDecCommitment(builder unsafe.Pointer, attr, decValue, decBlindingFactor string) error {
	cattr := C.CString(attr)
	defer C.free(unsafe.Pointer(cattr))
	cval := C.CString(decValue)
	defer C.free(unsafe.Pointer(cval))
	cfac := C.CString(decBlindingFactor)
	defer C.free(unsafe.Pointer(cfac))

	result := C.ursa_cl_credential_values_builder_add_dec_commitment(builder, cattr, cval, cfac)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}


	return nil
}

// FinalizeBuilder deallocates credential values builder and returns credential values entity instead
func FinalizeBuilder(builder unsafe.Pointer) (unsafe.Pointer, error) {
	var values unsafe.Pointer
	result := C.ursa_cl_credential_values_builder_finalize(builder, &values)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return values, nil
}

// FreeCredentialValues deallocates credential values instance
func FreeCredentialValues(values unsafe.Pointer) error {
	result := C.ursa_cl_credential_values_free(values)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}
