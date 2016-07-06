package credential

// TODO: properly comment all data structures and functions
import (
	"encoding/xml"
	"math/big"
)

const (
	//XMLHeader can be a used as the XML header when writing keys in XML format.
	XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
)

// SecretKey represents an issuer's secret (private) key.
type SecretKey struct {
	XMLName xml.Name `xml:"http://www.zurich.ibm.com/security/idemix IssuerPrivateKey"`
	P       big.Int  `xml:"Elements>p"`
	Q       big.Int  `xml:"Elements>q"`
	PPrime  big.Int  `xml:"Elements>pPrime"`
	QPrime  big.Int  `xml:"Elements>qPrime"`
}

// NewSecretKey creates a new issuer secret key using the provided parameters.
func NewSecretKey(p, q *big.Int) *SecretKey {
	sk := SecretKey{P: *p, Q: *q}

	sk.PPrime.Sub(p, bigONE)
	sk.PPrime.Rsh(&sk.PPrime, 1)

	sk.QPrime.Sub(q, bigONE)
	sk.QPrime.Rsh(&sk.QPrime, 1)

	return &sk
}

// xmlBases is an auxiliary struct to encode/decode the odd way bases are
// represented in the xml representation of public keys
type xmlBases struct {
	Num   int      `xml:"num,attr"`
	Base0 *big.Int `xml:"Base_0"`
	Base1 *big.Int `xml:"Base_1"`
	Base2 *big.Int `xml:"Base_2"`
	Base3 *big.Int `xml:"Base_3"`
	Base4 *big.Int `xml:"Base_4"`
	Base5 *big.Int `xml:"Base_5"`
}

// xmlFeatures is an auxiliary struct to make the XML encoding/decoding a bit
// easier while keeping the struct for PublicKey somewhat simple.
type xmlFeatures struct {
	Epoch struct {
		Length int `xml:"length,attr"`
	}
}

// Bases is a type that is introduced to simplify the encoding/decoding of
// a PublicKey whilst using the xml support of Go's standard library.
type Bases []*big.Int

// UnmarshalXML is an internal function to simplify decoding a PublicKey from
// XML.
func (bl *Bases) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var t xmlBases

	if err := d.DecodeElement(&t, &start); err != nil {
		return err
	}
	*bl = Bases{t.Base0, t.Base1, t.Base2, t.Base3, t.Base4, t.Base5}
	return nil
}

// MarshalXML is an internal function to simplify encoding a PublicKey to XML.
func (bl *Bases) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	t := xmlBases{Num: len(*bl), Base0: (*bl)[0], Base1: (*bl)[1], Base2: (*bl)[2], Base3: (*bl)[3], Base4: (*bl)[4], Base5: (*bl)[5]}
	return e.EncodeElement(t, start)
}

// EpochLength is a type that is introduced to simplify the encoding/decoding of
// a PublicKey whilst using the xml support of Go's standard library.
type EpochLength int

// UnmarshalXML is an internal function to simplify decoding a PublicKey from
// XML.
func (el *EpochLength) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var t xmlFeatures

	if err := d.DecodeElement(&t, &start); err != nil {
		return err
	}
	*el = EpochLength(t.Epoch.Length)
	return nil
}

// MarshalXML is an internal function to simplify encoding a PublicKey to XML.
func (el *EpochLength) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	var t xmlFeatures
	t.Epoch.Length = int(*el)
	return e.EncodeElement(t, start)
}

// PublicKey represents an issuer's public key.
type PublicKey struct {
	XMLName     xml.Name    `xml:"http://www.zurich.ibm.com/security/idemix IssuerPublicKey"`
	N           big.Int     `xml:"Elements>n"` // Modulus n
	Z           big.Int     `xml:"Elements>Z"` // Generator Z
	S           big.Int     `xml:"Elements>S"` // Generator S
	R           Bases       `xml:"Elements>Bases"`
	EpochLength EpochLength `xml:"Features"`
	Params      *SystemParameters
}

// NewPublicKey creates and returns a new public key based on the provided parameters.
func NewPublicKey(N, Z, S *big.Int, R []*big.Int) *PublicKey {
	pk := PublicKey{N: *N, Z: *Z, S: *S, R: R, Params: &DefaultSystemParameters}
	return &pk
}

// BaseParameters holds the base system parameters
type BaseParameters struct {
	Le      uint
	LePrime uint
	Lh      uint
	Lm      uint
	Ln      uint
	Lstatzk uint
	Lv      uint
}

var defaultBaseParameters = BaseParameters{
	Le:      597,
	LePrime: 120,
	Lh:      256,
	Lm:      256,
	Ln:      1024,
	Lstatzk: 80,
	Lv:      1700,
}

// DerivedParameters holds system parameters that can be drived from base
// systemparameters (BaseParameters)
type DerivedParameters struct {
	LeCommit      uint
	LmCommit      uint
	LRA           uint
	LsCommit      uint
	LvCommit      uint
	LvPrime       uint
	LvPrimeCommit uint
}

// makeDerivedParameters computes the derived system parameters
func makeDerivedParameters(base BaseParameters) DerivedParameters {
	return DerivedParameters{
		LeCommit:      base.LePrime + base.Lstatzk + base.Lh,
		LmCommit:      base.Lm + base.Lstatzk + base.Lh,
		LRA:           base.Ln + base.Lstatzk,
		LsCommit:      base.Lm + base.Lstatzk + base.Lh + 1,
		LvCommit:      base.Lv + base.Lstatzk + base.Lh,
		LvPrime:       base.Ln + base.Lstatzk,
		LvPrimeCommit: base.Ln + 2*base.Lstatzk + base.Lh,
	}
}

// SystemParameters holds the system parameters of the IRMA system.
type SystemParameters struct {
	BaseParameters
	DerivedParameters
}

// DefaultSystemParameters holds the default parameters as are currently in use
// at the moment. This might (and probably will) change in the future.
var DefaultSystemParameters = SystemParameters{defaultBaseParameters, makeDerivedParameters(defaultBaseParameters)}

// ParamSize computes the size of a parameter in bytes given the size in bits.
func ParamSize(a int) int {
	return (a + 8 - 1) / 8
}
