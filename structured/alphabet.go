package structured

import (
	"errors"

	"golang.org/x/exp/slices"
)

// ### About alphabets and the radix parameter

// The interfaces operate on strings, and the radix parameter determines which
// characters are valid within those strings, i.e. the alphabet. For example, if
// your radix is 10, then the alphabet for your plain text consists of the
// characters in the string "0123456789". If your radix is 16, then the
// alphabet is the characters in the string "0123456789abcdef".

// More concretely, if you want to encrypt, say, a 16 digit number grouped into
// 4 groups of 4 using a `-` as a delimiter as in `0123-4567-8901-2345`, then you
// would need a radix of at least 11, and you would need to translate the `-`
// character to an `a` (as that is the value that follows `9`) prior to the
// encryption. Conversely, you would need to translate an `a` to a `-` after
// decryption.

// This mapping of user inputs to alphabets defined by the radix is not performed
// by the library and must be done prior to calling the encrypt and after calling
// the decrypt functions.

// By default, a radix of up to 36 is supported, and the alphabet for a radix of
// 36 is "0123456789abcdefghijklmnopqrstuvwxyz". However, he interfaces allow the
// caller to specify a custom alphabet that differs from the default. Using a
// custom alphabet, radixes up to the number of characters in the alphabet can be
// supported. Note that custom alphabets must not contain duplicate characters.

const (
	defaultAlphabetStr = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

var defaultAlphabet, _ = NewAlphabet(defaultAlphabetStr)

type letter struct {
	val rune
	pos int
}

type Alphabet struct {
	def bool

	by_pos []rune
	by_val []letter
}

func NewAlphabet(s string) (Alphabet, error) {
	self := Alphabet{
		by_pos: []rune(s),
	}

	self.by_val = make([]letter, len(self.by_pos))
	for i, v := range self.by_pos {
		self.by_val[i] = letter{
			val: v,
			pos: i,
		}
	}
	slices.SortFunc(self.by_val,
		func(a, b letter) int {
			return int(a.val) - int(b.val)
		})

	for i := 1; i < len(self.by_val); i++ {
		if self.by_val[i] == self.by_val[i-1] {
			return Alphabet{}, errors.New(
				"duplicate letters found in alphabet")
		}
	}

	self.def = (len(s) <= len(defaultAlphabetStr)) &&
		(s == defaultAlphabetStr[:len(s)])

	return self, nil
}

func (self *Alphabet) Len() int {
	return len(self.by_pos)
}

func (self *Alphabet) IsDef() bool {
	return self.def
}

func (self *Alphabet) PosOf(c rune) int {
	idx, ok := slices.BinarySearchFunc(self.by_val, c,
		func(a letter, b rune) int {
			return int(a.val) - int(b)
		})
	if !ok {
		return -1
	}

	return self.by_val[idx].pos
}

func (self *Alphabet) ValAt(i int) rune {
	return self.by_pos[i]
}
