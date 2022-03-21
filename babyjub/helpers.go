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
	ysq := new(big.Int).Mod(new(big.Int).Mul(y, y), *constants.Q)
	lhs := new(big.Int).Sub(ysq, constants.One)
	rhs := new(big.Int).Sub(new(big.Int).Mod(new(big.Int).Mul(ysq, D), constants.Q), A)
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
