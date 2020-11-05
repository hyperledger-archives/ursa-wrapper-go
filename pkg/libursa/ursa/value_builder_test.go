package ursa

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestNewValueBuilder(t *testing.T) {
	t.Run("NewValueBuilder", func(t *testing.T) {
		builder, err := NewValueBuilder()
		assert.Empty(t, err)
		assert.NotEmpty(t, builder)
	})
}

func TestAddDecHidden(t *testing.T) {
	t.Run("AddDecHidden", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := AddDecHidden(builder, "master_secret", "122345")
		assert.Empty(t, err)
	})

	t.Run("AddDecHidden", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := AddDecHidden(builder, "master_secret", "fail")
		assert.NotEmpty(t, err)
	})
}

func TestAddDecKnown(t *testing.T) {
	t.Run("AddDecKnown", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := AddDecKnown(builder, "master_secret", "12a2345")
		assert.Empty(t, err)
	})

	t.Run("AddDecKnown", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := AddDecKnown(builder, "master_secret", "fail")
		assert.NotEmpty(t, err)
	})
}

func TestAddDecCommitment(t *testing.T) {
	t.Run("AddDecCommitment", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := AddDecCommitment(builder, "master_secret", "12345", "9876")
		assert.Empty(t, err)
	})

	t.Run("AddDecCommitment", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := AddDecCommitment(builder, "master_secret", "fail", "9876")
		assert.NotEmpty(t, err)
	})
}

func TestFinalizeBuilder(t *testing.T) {
	t.Run("FinalizeBuilder", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		values, err := FinalizeBuilder(builder)
		assert.Empty(t, err)
		assert.NotEmpty(t, values)
	})
}

func TestFreeCredentialValues(t *testing.T) {
	t.Run("FreeCredentialValues", func(t *testing.T) {
		var values unsafe.Pointer

		err := FreeCredentialValues(values)
		assert.NotEmpty(t, err)
	})
}
