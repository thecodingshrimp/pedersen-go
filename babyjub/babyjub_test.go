package babyjub

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"
)

func TestAdd1(t *testing.T) {
	a := &Point{X: big.NewInt(0), Y: big.NewInt(1)}
	b := &Point{X: big.NewInt(0), Y: big.NewInt(1)}

	c := NewPointProjective().Add(a.Projective(), b.Projective())
	// fmt.Printf("%v = 2 * %v", *c, *a)
	assert.Equal(t, "0", c.X.String())
	assert.Equal(t, "1", c.Y.String())
}

func TestAdd2(t *testing.T) {
	aX := utils.NewIntFromString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268")
	aY := utils.NewIntFromString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475")
	a := &Point{X: aX, Y: aY}

	bX := utils.NewIntFromString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268")
	bY := utils.NewIntFromString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475")
	b := &Point{X: bX, Y: bY}

	c := NewPointProjective().Add(a.Projective(), b.Projective())
	// fmt.Printf("%v = 2 * %v", *c, *a)
	assert.Equal(t,
		"6890855772600357754907169075114257697580319025794532037257385534741338397365",
		c.X.String())
	assert.Equal(t,
		"4338620300185947561074059802482547481416142213883829469920100239455078257889",
		c.Y.String())
}

func TestAdd3(t *testing.T) {
	aX := utils.NewIntFromString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268")
	aY := utils.NewIntFromString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475")
	a := &Point{X: aX, Y: aY}

	bX := utils.NewIntFromString(
		"16540640123574156134436876038791482806971768689494387082833631921987005038935")
	bY := utils.NewIntFromString(
		"20819045374670962167435360035096875258406992893633759881276124905556507972311")
	b := &Point{X: bX, Y: bY}

	c := NewPointProjective().Add(a.Projective(), b.Projective())
	// fmt.Printf("%v = 2 * %v", *c, *a)
	assert.Equal(t,
		"7916061937171219682591368294088513039687205273691143098332585753343424131937",
		c.X.String())
	assert.Equal(t,
		"14035240266687799601661095864649209771790948434046947201833777492504781204499",
		c.Y.String())
}

func TestAdd4(t *testing.T) {
	aX := utils.NewIntFromString(
		"0")
	aY := utils.NewIntFromString(
		"1")
	a := &Point{X: aX, Y: aY}

	bX := utils.NewIntFromString(
		"16540640123574156134436876038791482806971768689494387082833631921987005038935")
	bY := utils.NewIntFromString(
		"20819045374670962167435360035096875258406992893633759881276124905556507972311")
	b := &Point{X: bX, Y: bY}

	c := NewPointProjective().Add(a.Projective(), b.Projective())
	// fmt.Printf("%v = 2 * %v", *c, *a)
	assert.Equal(t,
		"16540640123574156134436876038791482806971768689494387082833631921987005038935",
		c.X.String())
	assert.Equal(t,
		"20819045374670962167435360035096875258406992893633759881276124905556507972311",
		c.Y.String())
}

func TestInCurve1(t *testing.T) {
	p := &Point{X: big.NewInt(0), Y: big.NewInt(1)}
	assert.Equal(t, true, p.InCurve())
}

func TestInCurve2(t *testing.T) {
	p := &Point{X: big.NewInt(1), Y: big.NewInt(0)}
	assert.Equal(t, false, p.InCurve())
}

func TestMul0(t *testing.T) {
	x := utils.NewIntFromString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268")
	y := utils.NewIntFromString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475")
	p := &Point{X: x, Y: y}
	s := utils.NewIntFromString("3")

	r2 := NewPointProjective().Add(p.Projective(), p.Projective())
	r2 = NewPointProjective().Add(r2, p.Projective())
	r := NewPoint().Mul(s, p)
	assert.Equal(t, r2.X.String(), r.X.String())
	assert.Equal(t, r2.Y.String(), r.Y.String())

	assert.Equal(t,
		"19372461775513343691590086534037741906533799473648040012278229434133483800898",
		r.X.String())
	assert.Equal(t,
		"9458658722007214007257525444427903161243386465067105737478306991484593958249",
		r.Y.String())
}

func TestMul1(t *testing.T) {
	x := utils.NewIntFromString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268")
	y := utils.NewIntFromString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475")
	p := &Point{X: x, Y: y}
	s := utils.NewIntFromString(
		"14035240266687799601661095864649209771790948434046947201833777492504781204499")
	r := NewPoint().Mul(s, p)
	assert.Equal(t,
		"17070357974431721403481313912716834497662307308519659060910483826664480189605",
		r.X.String())
	assert.Equal(t,
		"4014745322800118607127020275658861516666525056516280575712425373174125159339",
		r.Y.String())
}

func TestMul2(t *testing.T) {
	x := utils.NewIntFromString(
		"6890855772600357754907169075114257697580319025794532037257385534741338397365")
	y := utils.NewIntFromString(
		"4338620300185947561074059802482547481416142213883829469920100239455078257889")
	p := &Point{X: x, Y: y}
	s := utils.NewIntFromString(
		"20819045374670962167435360035096875258406992893633759881276124905556507972311")
	r := NewPoint().Mul(s, p)
	assert.Equal(t,
		"13563888653650925984868671744672725781658357821216877865297235725727006259983",
		r.X.String())
	assert.Equal(t,
		"8442587202676550862664528699803615547505326611544120184665036919364004251662",
		r.Y.String())
}

func TestInCurve3(t *testing.T) {
	x := utils.NewIntFromString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268")
	y := utils.NewIntFromString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475")
	p := &Point{X: x, Y: y}
	assert.Equal(t, true, p.InCurve())
}

func TestInCurve4(t *testing.T) {
	x := utils.NewIntFromString(
		"6890855772600357754907169075114257697580319025794532037257385534741338397365")
	y := utils.NewIntFromString(
		"4338620300185947561074059802482547481416142213883829469920100239455078257889")
	p := &Point{X: x, Y: y}
	assert.Equal(t, true, p.InCurve())
}

func TestInSubGroup1(t *testing.T) {
	x := utils.NewIntFromString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268")
	y := utils.NewIntFromString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475")
	p := &Point{X: x, Y: y}
	assert.Equal(t, true, p.InSubGroup())
}

func TestInSubGroup2(t *testing.T) {
	x := utils.NewIntFromString(
		"6890855772600357754907169075114257697580319025794532037257385534741338397365")
	y := utils.NewIntFromString(
		"4338620300185947561074059802482547481416142213883829469920100239455078257889")
	p := &Point{X: x, Y: y}
	assert.Equal(t, true, p.InSubGroup())
}

func TestCompressDecompress1(t *testing.T) {
	x := utils.NewIntFromString(
		"17777552123799933955779906779655732241715742912184938656739573121738514868268")
	y := utils.NewIntFromString(
		"2626589144620713026669568689430873010625803728049924121243784502389097019475")
	p := &Point{X: x, Y: y}

	buf := p.Compress()
	assert.Equal(t, "53b81ed5bffe9545b54016234682e7b2f699bd42a5e9eae27ff4051bc698ce85", hex.EncodeToString(buf[:]))

	p2, err := NewPoint().Decompress(buf)
	assert.Equal(t, nil, err)
	assert.Equal(t, p.X.String(), p2.X.String())
	assert.Equal(t, p.Y.String(), p2.Y.String())
}

func TestCompressDecompress2(t *testing.T) {
	x := utils.NewIntFromString(
		"6890855772600357754907169075114257697580319025794532037257385534741338397365")
	y := utils.NewIntFromString(
		"4338620300185947561074059802482547481416142213883829469920100239455078257889")
	p := &Point{X: x, Y: y}

	buf := p.Compress()
	assert.Equal(t, "e114eb17eddf794f063a68fecac515e3620e131976108555735c8b0773929709", hex.EncodeToString(buf[:]))

	p2, err := NewPoint().Decompress(buf)
	assert.Equal(t, nil, err)
	assert.Equal(t, p.X.String(), p2.X.String())
	assert.Equal(t, p.Y.String(), p2.Y.String())
}

func TestCompressDecompressRnd(t *testing.T) {
	for i := 0; i < 64; i++ {
		p1 := NewPoint().Mul(big.NewInt(int64(i)), B8)
		buf := p1.Compress()
		p2, err := NewPoint().Decompress(buf)
		assert.Equal(t, nil, err)
		assert.Equal(t, p1, p2)
	}
}
