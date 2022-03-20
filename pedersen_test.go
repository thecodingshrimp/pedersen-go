package pedersen

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/require"
	"github.com/thecodingshrimp/pedersen-go/babyjub"

	"github.com/stretchr/testify/assert"
)

func TestSmallerStringThanSegments(t *testing.T) {
	ph := New(zokratesName, 171)
	point, err := ph.PedersenHashBytes([]byte("0x"))
	assert.Nil(t, err)
	expectedX := utils.NewIntFromString("17663064468667073684455327659625297927281387087799066834838917694353926268364")
	expectedY := utils.NewIntFromString("836518895347192760941794050894826815287693227629880735401338905422596126957")
	expectedPoint := babyjub.NewPoint()
	expectedPoint.X = expectedX
	expectedPoint.Y = expectedY
	assert.Equal(t, expectedPoint, point)
}

func TestPedersen_HashBytes(t *testing.T) {
	ph := New(zokratesName, 0)
	point, err := ph.PedersenHashBytes([]byte("abc"))
	assert.Nil(t, err)
	expectedX := utils.NewIntFromString("9869277320722751484529016080276887338184240285836102740267608137843906399765")
	expectedY := utils.NewIntFromString("19790690237145851554496394080496962351633528315779989340140084430077208474328")
	expectedPoint := babyjub.NewPoint()
	expectedPoint.X = expectedX
	expectedPoint.Y = expectedY
	assert.Equal(t, expectedPoint, point)
}

func TestPedersen_HashBytes2(t *testing.T) {
	ph := New(zokratesName, 0)
	point, err := ph.PedersenHashBytes([]byte("abcdefghijklmnopqrstuvwx"))
	assert.Nil(t, err)
	expectedX := utils.NewIntFromString("3966548799068703226441887746390766667253943354008248106643296790753369303077")
	expectedY := utils.NewIntFromString("12849086395963202120677663823933219043387904870880733726805962981354278512988")
	expectedPoint := babyjub.NewPoint()
	expectedPoint.X = expectedX
	expectedPoint.Y = expectedY
	assert.Equal(t, expectedPoint, point)
}

// test case from zokrates_stdlib
// https://github.com/Zokrates/ZoKrates/blob/master/zokrates_stdlib/tests/tests/hashes/pedersen/512bit.zok
func TestPedersen_Zokrates(t *testing.T) {
	ph := New(zokratesName, 0)
	field512 := [512]byte{0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1}
	bytes := bitsToBytes(field512[:])
	// println(hex.EncodeToString(bytes))
	point, err := ph.PedersenHashBytes(bytes)
	require.NoError(t, err)
	// t.Log(point)
	h1 := bytes32ToBits(Compress_Zokrates(point))
	h0 := [256]byte{0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1}
	require.Equal(t, h0[:], h1)
}

// generate new test cases for zokrates
func TestPedersen_generate(t *testing.T) {
	ph := New(zokratesName, 0)
	eHex := "e24f1d03d1d81e94a099042736d40bd9681b867321443ff58a4568e274dbd83b"
	eBytes, _ := hex.DecodeString(eHex)
	eBits := bytesToBits(eBytes)
	// hPx1 - pedersen hash x1
	point, err := ph.PedersenHashBytes(eBytes, eBytes)
	require.NoError(t, err)
	hPx1Bits := bytes32ToBits(Compress_Zokrates(point))
	// hPx16, hPx32 - pedersen hash x16, x32
	var hPx16Bits []byte
	for i := 1; i < 32; i++ {
		prev := Compress_Zokrates(point)
		if i == 16 {
			hPx16Bits = bytes32ToBits(prev)
		}
		point, err = ph.PedersenHashBytes(prev[:], eBytes)
		require.NoError(t, err)
	}
	hPx32Bits := bytes32ToBits(Compress_Zokrates(point))

	// hSx1 - sha256 hash x1
	prev := sha256.Sum256(eBytes)
	hSx1Bits := bytesToBits(prev[:])
	// hSx16, hSx32 - sha256 hash x16, x32
	var hSx16Bits []byte
	for i := 1; i < 32; i++ {
		if i == 16 {
			hSx16Bits = bytesToBits(prev[:])
		}
		prev = sha256.Sum256(prev[:])
	}
	hSx32Bits := bytesToBits(prev[:])

	fmt.Printf("data bits: %v\n", bitsToFieldArray(eBits))
	fmt.Printf("petersen  x1: %v\n", bitsToFieldArray(hPx1Bits))
	fmt.Printf("petersen x16: %v\n", bitsToFieldArray(hPx16Bits))
	fmt.Printf("petersen x32: %v\n", bitsToFieldArray(hPx32Bits))
	fmt.Printf("sha256    x1: %v\n", bitsToFieldArray(hSx1Bits))
	fmt.Printf("sha256   x16: %v\n", bitsToFieldArray(hSx16Bits))
	fmt.Printf("sha256   x32: %v\n", bitsToFieldArray(hSx32Bits))
}
