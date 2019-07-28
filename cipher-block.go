package blowcbc // import "github.com/dmitrysigaev/blowcbc"

// getNextWord returns the next big-endian uint32 value from the byte slice
// at the given position in a circular manner, updating the position.
func getNextWord(b []byte, pos *int) uint32 {
	var w uint32
	j := *pos
	for i := 0; i < 4; i++ {
		w = w<<8 | uint32(b[j])
		j++
		if j >= len(b) {
			j = 0
		}
	}
	*pos = j
	return w
}

// ExpandKey performs a key expansion on the given *Cipher. Specifically, it
// performs the Blowfish algorithm's key schedule which sets up the *Cipher's
// pi and substitution tables for calls to Encrypt. This is used, primarily,
// by the bcrypt package to reuse the Blowfish key schedule during its
// set up. It's unlikely that you need to use this directly.
func ExpandKey(key []byte, c *Cipher) {
	j := 0
	for i := 0; i < 18; i++ {
		// Using inlined getNextWord for performance.
		var d uint32
		for k := 0; k < 4; k++ {
			d = d<<8 | uint32(key[j])
			j++
			if j >= len(key) {
				j = 0
			}
		}
		c.p[i] ^= d
	}

	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}
	for i := 0; i < 256; i += 2 {
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

// This is similar to ExpandKey, but folds the salt during the key
// schedule. While ExpandKey is essentially expandKeyWithSalt with an all-zero
// salt passed in, reusing ExpandKey turns out to be a place of inefficiency
// and specializing it here is useful.
func expandKeyWithSalt(key []byte, salt []byte, c *Cipher) {
	j := 0
	for i := 0; i < 18; i++ {
		c.p[i] ^= getNextWord(key, &j)
	}

	j = 0
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.p[i], c.p[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s0[i], c.s0[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s1[i], c.s1[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s2[i], c.s2[i+1] = l, r
	}

	for i := 0; i < 256; i += 2 {
		l ^= getNextWord(salt, &j)
		r ^= getNextWord(salt, &j)
		l, r = encryptBlock(l, r, c)
		c.s3[i], c.s3[i+1] = l, r
	}
}

func round(a, b uint32, n int, c *Cipher) uint32 {
	return (c.s0[byte(b>>24)] + c.s1[byte(b>>16)]) ^ c.s2[byte(b>>8)] + c.s3[byte(b)] ^ c.p[n] ^ a
}

func encryptBlock(l, r uint32, c *Cipher) (uint32, uint32) {
	xl, xr := l, r
	xl ^= c.p[0]
	for i := 0; i < c.round; i += 2 {
		xr = round(xr, xl, i+1, c)
		xl = round(xl, xr, i+2, c)
	}
	xr ^= p[c.round+1]
	return xr, xl
}

func decryptBlock(l, r uint32, c *Cipher) (uint32, uint32) {
	xl, xr := l, r
	xl ^= c.p[c.round+1]
	for i := c.round; i > 0; i -= 2 {
		xr = round(xr, xl, i, c)
		xl = round(xl, xr, i-1, c)
	}
	xr ^= c.p[0]
	return xr, xl
}
