package ursa

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMasterSecret(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		ms, err := NewMasterSecret()
		assert.NoError(t, err)

		js, err := ms.ToJSON()
		assert.NoError(t, err)

		m := struct {
			MasterSecret string `json:"ms"`
		}{}
		err = json.Unmarshal(js, &m)
		assert.NoError(t, err)

		i := new(big.Int)
		_, ok := i.SetString(m.MasterSecret, 10)
		assert.True(t, ok)

		ms, err = MasterSecretFromJSON(js)
		assert.NoError(t, err)
		assert.NotEmpty(t, ms)

		err = ms.Free()
		assert.NoError(t, err)
	})

	t.Run("bad json", func(t *testing.T) {
		ms, err := MasterSecretFromJSON([]byte(`{"t": "123"}`))
		assert.Error(t, err)
		assert.Empty(t, ms)
	})
}
