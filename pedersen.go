package pedersen

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"log"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/pkg/errors"
	babyjubHelper "github.com/thecodingshrimp/pedersen-go/babyjub"
)

const zokratesName = "test"

type PedersenHash struct {
	name          string
	segments      int
	generators    []babyjub.Point
	isSized       bool
	hasher256hash hasher
}

func New(name string, segments int) *PedersenHash {
	ph := new(PedersenHash)
	switch name {
	case "":
		ph.name = zokratesName
	default:
		ph.name = name
	}

	ph.hasher256hash = makeHasher(sha256.New())

	if segments > 0 {
		ph.isSized = true
		ph.segments = segments
		ph.createGenerators()
	}

	return ph
}

func (ph *PedersenHash) createGenerators() []babyjub.Point {
	ph.generators = make([]babyjub.Point, ph.segments)
	segments := ph.segments
	var current *babyjub.Point
	var err error
	for i := 0; i < segments; i++ {
		if i%62 == 0 {
			current, err = ph.pedersenHashBasePoint(i / 62)
			if err != nil {
				log.Fatalf(err.Error())
				return nil
			}
		}
		j := i % 62
		if j != 0 {
			currentProjective := current.Projective()
			currentProjective = babyjub.NewPointProjective().Add(currentProjective, currentProjective)
			currentProjective = babyjub.NewPointProjective().Add(currentProjective, currentProjective)
			currentProjective = babyjub.NewPointProjective().Add(currentProjective, currentProjective)
			currentProjective = babyjub.NewPointProjective().Add(currentProjective, currentProjective)
			current = currentProjective.Affine()
		}
		ph.generators[i] = *current
	}
	return ph.generators
}

// https://github.com/ethereum/go-ethereum/blob/667e1c038e171fafb6e2136b02f8b01dd559cacf/consensus/ethash/algorithm.go#L95
// hasher is a repetitive hasher allowing the same hash data structures to be
// reused between hash runs instead of requiring new ones to be created.
type hasher func(data []byte) []byte

// https://github.com/ethereum/go-ethereum/blob/667e1c038e171fafb6e2136b02f8b01dd559cacf/consensus/ethash/algorithm.go#L100
// makeHasher creates a repetitive hasher, allowing the same hash data structures to
// be reused between hash runs instead of requiring new ones to be created. The returned
// function is not thread safe!
func makeHasher(h hash.Hash) hasher {
	return func(data []byte) []byte {
		h.Reset()
		h.Write(data)
		return h.Sum(nil)
	}
}

func (ph *PedersenHash) pedersenHashBasePoint(i int) (*babyjub.Point, error) {
	if i > 0xFFFF {
		return nil, errors.New("Sequence number invalid")
	}
	if len(ph.name) > 28 {
		return nil, errors.New("Name too long")
	}
	// data = b"%-28s%04X" % (name, i)
	formattedStr := fmt.Sprintf("%-28s%04X", ph.name, i)
	data := []byte(formattedStr)

	return babyjubHelper.FromBytes(ph.hasher256hash(data))
}

func (ph *PedersenHash) pedersenHashWindows(windows []byte) (*babyjub.Point, error) {
	if !ph.isSized {
		ph.segments = len(windows)
		ph.isSized = true
		ph.createGenerators()
	}

	if len(windows) > ph.segments {
		errorMessage := fmt.Sprintf("Number of windows exceeds pedersenHasher config. %d vs. %d", len(windows), ph.segments)
		log.Fatalf(errorMessage)
		return nil, errors.New(errorMessage)
	}

	padding := (ph.segments - len(windows))
	if padding > 0 {
		windows = append(windows, make([]byte, padding)...)
	}

	result := babyjub.NewPoint().Projective()
	segment := babyjub.NewPoint()
	allocedInt := big.NewInt(0)
	allocedPointProjective := babyjub.NewPointProjective()
	for j, window := range windows {
		segment = segment.Mul(allocedInt.SetInt64(int64((window&0x3)+1)), &ph.generators[j])
		if window > 0x3 {
			segment.X = segment.X.Neg(segment.X)
		}
		result = result.Add(result, babyjubHelper.SetPointProjective(segment, allocedPointProjective))
	}
	return result.Affine(), nil
}

func (ph *PedersenHash) PedersenHashBytes(bytesArray ...[]byte) (*babyjub.Point, error) {
	bytes := []byte{}
	for _, item := range bytesArray {
		bytes = append(bytes, item...)
	}
	if len(bytes) == 0 {
		return nil, errors.New("Cannot hash on null bytes")
	}
	// Split into 3 bit windows
	bitsLen := len(bytes) * 8
	var windows []byte
	round := bitsLen / 3
	if bitsLen%3 != 0 {
		round++
	}
	for i := 0; i < round; i++ {
		result, err := get3BitsAt(i*3, bytes)
		if err != nil {
			return nil, err
		}
		windows = append(windows, result)
	}
	return ph.pedersenHashWindows(windows)
}
