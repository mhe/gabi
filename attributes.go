package gabi

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"time"
)

const (
	// ExpiryFactor is the precision for the expiry attribute. Value is one week.
	ExpiryFactor = 60 * 60 * 24 * 7
	// ValidityDefault is the default validity of new credentials (half a year).
	ValidityDefault = 52 / 2
	metadataLength  = 1 + 3 + 2 + 2 + 16
)

var (
	metadataVersion = []byte{0x02}

	versionField     = MetadataField{1, 0}
	signingDateField = MetadataField{3, 1}
	validityField    = MetadataField{2, 4}
	keyCounterField  = MetadataField{2, 6}
	credentialID     = MetadataField{16, 8}
)

// MetadataField contains the length and offset of a field within a metadata attribute.
type MetadataField struct {
	length int
	offset int
}

// MetadataAttribute represent a metadata attribute. Contains th credential type, signing date, validity, and the public key counter.
type MetadataAttribute struct {
	*big.Int
}

// MetadataFromInt wraps the given Int
func MetadataFromInt(i *big.Int) *MetadataAttribute {
	return &MetadataAttribute{Int: i}
}

// NewMetadataAttribute constructs a new instance containing the default values:
// 0x02 as versionField
// now as signing date
// 0 as keycounter
// ValidityDefault (half a year) as default validity.
func NewMetadataAttribute() *MetadataAttribute {
	val := MetadataAttribute{new(big.Int)}
	val.setField(versionField, metadataVersion)
	val.setSigningDate()
	val.setKeyCounter(0)
	val.setValidityDuration(ValidityDefault)
	return &val
}

// Bytes returns this metadata attribute as a byte slice.
func (attr *MetadataAttribute) Bytes() []byte {
	bytes := attr.Int.Bytes()
	if len(bytes) < metadataLength {
		bytes = append(bytes, make([]byte, metadataLength-len(bytes))...)
	}
	return bytes
}

// Version returns the metadata version of this instance
func (attr *MetadataAttribute) Version() byte {
	return attr.field(versionField)[0]
}

// SigningDate returns the time at which this instance was signed
func (attr *MetadataAttribute) SigningDate() time.Time {
	bytes := attr.field(signingDateField)
	bytes = bytes[1:] // The signing date field is one byte too long
	timestamp := int64(binary.BigEndian.Uint16(bytes)) * ExpiryFactor
	return time.Unix(timestamp, 0)
}

func (attr *MetadataAttribute) setSigningDate() {
	attr.setField(signingDateField, shortToByte(int(time.Now().Unix()/ExpiryFactor)))
}

// KeyCounter return the public key counter of the metadata attribute
func (attr *MetadataAttribute) KeyCounter() int {
	return int(binary.BigEndian.Uint16(attr.field(keyCounterField)))
}

func (attr *MetadataAttribute) setKeyCounter(i int) {
	attr.setField(keyCounterField, shortToByte(i))
}

// ValidityDuration returns the amount of epochs during which this instance is valid
func (attr *MetadataAttribute) ValidityDuration() int {
	return int(binary.BigEndian.Uint16(attr.field(validityField)))
}

func (attr *MetadataAttribute) setValidityDuration(weeks int) {
	attr.setField(validityField, shortToByte(weeks))
}

// CredentialType returns the credential type of the current instance
// using the MetaStore.
func (attr *MetadataAttribute) CredentialType() *CredentialType {
	return MetaStore.hashToCredentialType(attr.field(credentialID))
}

func (attr *MetadataAttribute) setCredentialIdentifier(id string) {
	bytes := sha256.Sum256([]byte(id))
	attr.setField(credentialID, bytes[:16])
}

// Expiry returns the expiry date of this instance
func (attr *MetadataAttribute) Expiry() time.Time {
	expiry := attr.SigningDate().Unix() + int64(attr.ValidityDuration()*ExpiryFactor)
	return time.Unix(expiry, 0)
}

// IsValidOn returns whether this instance is still valid at the given time
func (attr *MetadataAttribute) IsValidOn(t time.Time) bool {
	return attr.Expiry().After(t)
}

// IsValid returns whether this instance is valid.
func (attr *MetadataAttribute) IsValid() bool {
	return attr.IsValidOn(time.Now())
}

func (attr *MetadataAttribute) field(field MetadataField) []byte {
	return attr.Bytes()[field.offset : field.offset+field.length]
}

func (attr *MetadataAttribute) setField(field MetadataField, value []byte) {
	if len(value) > field.length {
		panic("Specified metadata field too large")
	}

	bytes := attr.Bytes()

	// Push the value to the right within the field. Graphical representation:
	// --xxxXXX----
	// "-" indicates a byte of another field
	// "X" is a byte of the value and "x" of our field
	// In this example, our field has offset 2, length 6,
	// but the specified value is only 3 bytes long.
	startindex := field.length - len(value)
	for i := 0; i < field.length; i++ {
		if i < startindex {
			bytes[i+field.offset] = 0
		} else {
			bytes[i+field.offset] = value[i-startindex]
		}
	}

	attr.SetBytes(bytes)
}

func shortToByte(x int) []byte {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, uint16(x))
	return bytes
}
