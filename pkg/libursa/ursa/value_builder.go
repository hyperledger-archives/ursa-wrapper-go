package ursa

/*
   #cgo LDFLAGS: -lursa
   #include "ursa_cl.h"
   #include <stdlib.h>
*/
import "C"
import (
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"unsafe"
)

type CredentialValuesBuilder Handle
type CredentialValues Handle

// NewValuesBuilder creates and returns credentials values entity builder
func NewValueBuilder() (*CredentialValuesBuilder, error) {
	var builder unsafe.Pointer

	result := C.ursa_cl_credential_values_builder_new(&builder)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialValuesBuilder{builder}, nil
}

// AddDecHidden adds new hidden attribute dec_value to credential values map
func (r *CredentialValuesBuilder) AddDecHidden(attr, decValue string) error {
	cattr := C.CString(attr)
	defer C.free(unsafe.Pointer(cattr))

	cval := C.CString(decValue)
	defer C.free(unsafe.Pointer(cval))

	result := C.ursa_cl_credential_values_builder_add_dec_hidden(r.ptr, cattr, cval)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// AddDecKnown adds new known attribute dec_value to credential values map
func (r *CredentialValuesBuilder) AddDecKnown(attr, decValue string) error {
	cattr := C.CString(attr)
	defer C.free(unsafe.Pointer(cattr))

	cval := C.CString(decValue)
	defer C.free(unsafe.Pointer(cval))

	result := C.ursa_cl_credential_values_builder_add_dec_known(r.ptr, cattr, cval)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// AddDecCommitment adds new hidden attribute dec_value to credential values map
func (r *CredentialValuesBuilder) AddDecCommitment(attr, decValue, decBlindingFactor string) error {
	cattr := C.CString(attr)
	defer C.free(unsafe.Pointer(cattr))
	cval := C.CString(decValue)
	defer C.free(unsafe.Pointer(cval))
	cfac := C.CString(decBlindingFactor)
	defer C.free(unsafe.Pointer(cfac))

	result := C.ursa_cl_credential_values_builder_add_dec_commitment(r.ptr, cattr, cval, cfac)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

// FinalizeBuilder deallocates credential values builder and returns credential values entity instead
func (r *CredentialValuesBuilder) Finalize() (*CredentialValues, error) {
	var values unsafe.Pointer
	result := C.ursa_cl_credential_values_builder_finalize(r.ptr, &values)
	if result.code != 0 {
		return nil, ursaError(C.GoString(result.message))
	}

	return &CredentialValues{values}, nil
}

// FreeCredentialValues deallocates credential values instance
func (r *CredentialValues) Free() error {
	result := C.ursa_cl_credential_values_free(r.ptr)
	if result.code != 0 {
		return ursaError(C.GoString(result.message))
	}

	return nil
}

func EncodeValue(raw interface{}) string {
	var enc string

	switch v := raw.(type) {
	case nil:
		enc = ToEncodedNumber("None")
	case string:
		i, err := strconv.Atoi(v)
		if err == nil && (i <= math.MaxInt32 && i >= math.MinInt32) {
			enc = v
		} else {
			enc = ToEncodedNumber(v)
		}
	case bool:
		if v {
			enc = "1"
		} else {
			enc = "0"
		}
	case int32:
		enc = strconv.Itoa(int(v))
	case int64:
		if v <= math.MaxInt32 && v >= math.MinInt32 {
			enc = strconv.Itoa(int(v))
		} else {
			enc = ToEncodedNumber(strconv.Itoa(int(v)))
		}
	case int:
		if v <= math.MaxInt32 && v >= math.MinInt32 {
			enc = strconv.Itoa(v)
		} else {
			enc = ToEncodedNumber(strconv.Itoa(v))
		}
	case float64:
		if v == 0 {
			enc = ToEncodedNumber("0.0")
		} else {
			enc = ToEncodedNumber(fmt.Sprintf("%f", v))
		}
	default:
		//Not sure what to do with Go and unknown types...  this works for now
		enc = ToEncodedNumber(fmt.Sprintf("%v", v))
	}

	return enc
}

func ToEncodedNumber(raw string) string {
	b := []byte(raw)
	hasher := sha256.New()
	hasher.Write(b)

	sh := hasher.Sum(nil)
	i := new(big.Int)
	i.SetBytes(sh)

	return i.String()
}
