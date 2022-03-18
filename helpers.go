package pedersen

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/thecodingshrimp/pedersen-go/babyjub"
)

func getBitAt(index int, bytes []byte) (byte, error) {
	startByte := index / 8
	if startByte > len(bytes)-1 {
		return byte(0), errors.New("out of index")
	}
	bit := byte(0x80) >> uint(index%8)
	if bytes[startByte]&bit == 0 {
		return 0, nil
	} else {
		return 1, nil
	}
}

func get3BitsAt(index int, bytes []byte) (byte, error) {
	firstBit, err := getBitAt(index, bytes)
	if err != nil {
		return 0, err
	}
	secondBit, err := getBitAt(index+1, bytes)
	if err != nil {
		return firstBit, nil
	}
	thirdBit, err := getBitAt(index+2, bytes)
	if err != nil {
		return (secondBit << 1) | firstBit, nil
	}
	return (thirdBit << 2) | (secondBit << 1) | firstBit, nil
}

// Encode binary integer array to bytes.
// The input integer array can only contains elements of 0 or 1.
// This function can be used to convert the binary representation of the field array in zokrates.
// If the length is not a multiple of 8 then 0 is automatically added at the end.
func bitsToBytes(bits []byte) []byte {
	n := len(bits)
	if n == 0 {
		return []byte{}
	}
	for i := (n-1)%8 + 1; i < 8; i++ {
		bits = append(bits, 0)
	}
	bytes := make([]byte, n/8)
	for i, b := range bits {
		p := i / 8
		if b == 1 {
			bytes[p] |= byte(0x80) >> (i % 8)
		} else if b != 0 {
			panic(fmt.Errorf("invalid bit (%d)", i))
		}
	}
	return bytes
}

// This is the reverse conversion function of bitsToBytes
func bytesToBits(bytes []byte) []byte {
	bits := make([]byte, 8*len(bytes))
	p := 0
	for _, v := range bytes {
		for j := 0; j < 8; j++ {
			if (v & (byte(0x80) >> j)) != 0 {
				bits[p] = 1
			}
			p++
		}
	}
	return bits
}

func bytes32ToBits(bytes32 [32]byte) []byte {
	return bytesToBits(bytes32[:])
}

// convert bits to zokrates field array
func bitsToFieldArray(bits []byte) string {
	sb := strings.Builder{}
	sb.WriteString("[")
	for i, v := range bits {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(strconv.Itoa(int(v)))
	}
	sb.WriteString("]")
	return sb.String()
}

// Pack point method reference from edwardsCompress.zok in zokrates
func Compress_Zokrates(point *babyjub.Point) [32]byte {
	yBytes := point.Y.Bytes()
	res := [32]byte{}
	copy(res[len(res)-len(yBytes):], yBytes)
	// use odd or even, not sign
	if point.X.Mod(point.X, big.NewInt(2)).Cmp(big.NewInt(1)) == 0 {
		res[0] = res[0] | 0x80
	}
	return res
}
