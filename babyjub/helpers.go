package babyjub

import (
	"errors"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/constants"
)

var C *big.Int

func init() {
	C = big.NewInt(8)
}

func FromY(y *big.Int) (*babyjub.Point, error) {
	//x^2 = (y^2 - 1) / (d * y^2 - a)
	//ysq = y * y mod Q
	ysq := new(big.Int).Mod(new(big.Int).Mul(y, y), constants.Q)
	lhs := new(big.Int).Sub(ysq, constants.One)
	rhs := new(big.Int).Sub(new(big.Int).Mod(new(big.Int).Mul(ysq, babyjub.D), constants.Q), babyjub.A)
	//lhs / rhs mod Q
	xsq := new(big.Int).Mod(new(big.Int).Mul(lhs, new(big.Int).ModInverse(rhs, constants.Q)), constants.Q)
	x := new(big.Int).ModSqrt(xsq, constants.Q)

	if x == nil {
		return nil, errors.New("Sqrt Non Exists")
	}
	tmp := new(big.Int).Sub(constants.Q, x)
	//use the bigger sqrt
	if x.Cmp(tmp) == -1 {
		x.Set(tmp)
	}

	result := babyjub.NewPoint()
	result.X = new(big.Int).Mod(x, constants.Q)
	result.Y = new(big.Int).Mod(y, constants.Q)
	return result, nil
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

// Projective returns a PointProjective from the Point
func SetPointProjective(p *babyjub.Point, pr *babyjub.PointProjective) *babyjub.PointProjective {
	pr.X.SetBigInt((*big.Int)(p.X))
	pr.Y.SetBigInt((*big.Int)(p.Y))
	pr.Z.SetOne()
	return pr
}

func FromBytes(bytes []byte) (*babyjub.Point, error) {
	y := new(big.Int).SetBytes(bytes)
	y = new(big.Int).Mod(y, constants.Q)
	for {
		p, err := FromY(y)
		if err != nil {
			y = y.Add(y, constants.One)
		} else {
			p = babyjub.NewPoint().Mul(C, p)
			if p.InSubGroup() {
				return p, nil
			} else {
				return nil, errors.New("Point not on prime-ordered subgroup")
			}
		}
	}
}
