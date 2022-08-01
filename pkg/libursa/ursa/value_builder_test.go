package ursa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewValueBuilder(t *testing.T) {
	t.Run("NewValueBuilder", func(t *testing.T) {
		builder, err := NewValueBuilder()
		assert.Empty(t, err)
		assert.NotEmpty(t, builder)

		err = builder.AddDecHidden("master_secret", "122345")
		assert.NoError(t, err)

		vals, err := builder.Finalize()
		assert.NoError(t, err)

		str, err := vals.ToJSON()
		assert.NoError(t, err)

		err = vals.Free()
		assert.NoError(t, err)

		newVals, err := CredentialValuesFromJSON(str)
		assert.NoError(t, err)
		assert.NotNil(t, newVals)
	})
}

func TestAddDecHidden(t *testing.T) {
	t.Run("AddDecHidden", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := builder.AddDecHidden("master_secret", "122345")
		assert.Empty(t, err)
	})

	t.Run("AddDecHidden", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := builder.AddDecHidden("master_secret", "fail")
		assert.NotEmpty(t, err)
	})
}

func TestAddDecKnown(t *testing.T) {
	t.Run("AddDecKnown", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := builder.AddDecKnown("master_secret", "12a2345")
		assert.Empty(t, err)
	})

	t.Run("AddDecKnown", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := builder.AddDecKnown("master_secret", "fail")
		assert.NotEmpty(t, err)
	})
}

func TestAddDecCommitment(t *testing.T) {
	t.Run("AddDecCommitment", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := builder.AddDecCommitment("master_secret", "12345", "9876")
		assert.Empty(t, err)
	})

	t.Run("AddDecCommitment", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		err := builder.AddDecCommitment("master_secret", "fail", "9876")
		assert.NotEmpty(t, err)
	})
}

func TestFinalizeBuilder(t *testing.T) {
	t.Run("FinalizeBuilder", func(t *testing.T) {
		builder, _ := NewValueBuilder()

		values, err := builder.Finalize()
		assert.Empty(t, err)
		assert.NotEmpty(t, values)
	})
}
