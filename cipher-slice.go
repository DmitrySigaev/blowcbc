package blowcbc // import "github.com/dmitrysigaev/blowcbc"

import (
	"crypto/rand"
	"strconv"
)

// The Blowfish block size in bytes.
const BlockSize = 8

// A Cipher is an instance of Blowfish encryption using a particular key.
type Cipher struct {
	p              [268]uint32
	s0, s1, s2, s3 [256]uint32
	round          int
	IV             [8]byte
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/blowfish: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a Cipher.
// The key argument should be the Blowfish key, from 1 to 56 bytes.
func NewCipher(key []byte) (*Cipher, error) {
	var result Cipher
	if k := len(key); k < 1 || k > 56 {
		return nil, KeySizeError(k)
	}
	initCipher(&result, 16)
	ExpandKey(key, &result)
	return &result, nil
}

// NewSaltedCipher creates a returns a Cipher that folds a salt into its key
// schedule. For most purposes, NewCipher, instead of NewSaltedCipher, is
// sufficient and desirable. For bcrypt compatibility, the key can be over 56
// bytes.
func NewSaltedCipher(key, salt []byte) (*Cipher, error) {
	if len(salt) == 0 {
		return NewCipher(key)
	}
	var result Cipher
	if k := len(key); k < 1 {
		return nil, KeySizeError(k)
	}
	initCipher(&result, 16)
	expandKeyWithSalt(key, salt, &result)
	return &result, nil
}

// BlockSize returns the Blowfish block size, 8 bytes.
// It is necessary to satisfy the Block interface in the
// package "crypto/cipher".
func (c *Cipher) BlockSize() int { return BlockSize }

// Encrypt encrypts the 8-byte buffer src using the key k
// and stores the result in dst.
// Note that for amounts of data larger than a block,
// it is not safe to just call Encrypt on successive blocks;
// instead, use an encryption mode like CBC (see crypto/cipher/cbc.go).
func (c *Cipher) EncryptBlock(dst, src []byte) {
	l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	l, r = encryptBlock(l, r, c)
	dst[0], dst[1], dst[2], dst[3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	dst[4], dst[5], dst[6], dst[7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)
}

// Decrypt decrypts the 8-byte buffer src using the key k
// and stores the result in dst.
func (c *Cipher) DecryptBlock(dst, src []byte) {
	l := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	l, r = decryptBlock(l, r, c)
	dst[0], dst[1], dst[2], dst[3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	dst[4], dst[5], dst[6], dst[7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)
}

func padDataEn(data []byte, length int) ([]byte, int) {
	paddedLength := 16

	//if IvSpace, leave a blank block at the front
	if length&7 == 0 {
		paddedLength += length
	} else { //pad the data to a multiple of 8 plus one block
		paddedLength += length + 8 - (length & 7)
	}
	//fill the new array with the data
	outData := make([]byte, paddedLength)
	for i := 0; i < length; i++ {
		outData[8+i] = data[i]
	}
	//add the padding character to the end
	for i := length + 8; i < paddedLength; i++ {
		outData[i] = (outData[length-1+8] ^ 0xCC) //fill the padding with a character that is different from the last character in the plaintext, so we can find the end later
	}
	return outData, paddedLength
}

func (c *Cipher) EnCrypt_CBC(data []byte, length int) ([]byte, int) {
	len, err := rand.Read(c.IV[:])
	if len != 8 && err != nil {
		return data, length
	}

	outData, newlength := padDataEn(data, length)
	for i := 0; i < 8; i++ {
		outData[i] = c.IV[i]
	}

	for i := 8; i < newlength; i += 8 { //run the encryption
		for k := 0; k < 8; k++ {
			outData[i+k] ^= outData[k+i-8]
		}
		c.EncryptBlock(outData[i:i+8], outData[i:i+8])
	}

	return outData, newlength
}

func padDataDe(data []byte, length int) ([]byte, int) {
	paddedLength := length
	//if IvSpace, leave a blank block at the front
	if length&7 != 0 {
		return nil, 0
	}
	//fill the new array with the data
	outData := make([]byte, paddedLength)
	for i := 0; i < length; i++ {
		outData[i] = data[i]
	}
	//add the padding character to the end
	for i := length; i < paddedLength; i++ {
		outData[i] = (outData[length-1] ^ 0xCC) //fill the padding with a character that is different from the last character in the plaintext, so we can find the end later
	}
	return outData, paddedLength
}

func findPaddingEnd(data []byte, length int) int {
	i := length
	for data[i-1] == data[length-1] {
		i-- //find the first character from the back that isnt the same as the last character
	}
	return i //retun the length without the padding
}

func (c *Cipher) DeCrypt_CBC(data []byte, length int) ([]byte, int) {

	outData, newlength := padDataDe(data, length)
	for i := 0; i < 8; i++ {
		c.IV[i] = outData[i]
	}

	var nextIV [8]byte
	for i := 8; i < newlength; i += 8 { //run the encryption
		for k := 0; k < 8; k++ {
			nextIV[k] = outData[k+i]
		}
		c.DecryptBlock(outData[i:i+8], outData[i:i+8])
		for k := 0; k < 8; k++ {
			outData[i+k] ^= c.IV[k]
			c.IV[k] = nextIV[k]
		}
	}

	newlength = findPaddingEnd(outData, newlength) - 8
	return outData[8 : newlength+8], newlength
}

func initCipher(c *Cipher, round int) {
	copy(c.p[0:], p[0:])
	copy(c.s0[0:], s0[0:])
	copy(c.s1[0:], s1[0:])
	copy(c.s2[0:], s2[0:])
	copy(c.s3[0:], s3[0:])
	c.round = round
}
