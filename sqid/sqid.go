// Package sqid encodes internal int64 IDs (BIGSERIAL / INTEGER PRIMARY KEY)
// as opaque Sqids strings for the API surface. Encode in handler responses;
// decode path params back to int64 before touching the service/repo layer,
// and never treat the encoded string as anything but opaque.
package sqid

import (
	"errors"
	"fmt"

	"github.com/sqids/sqids-go"
)

// ErrInvalidID is returned by Decode for any string that doesn't decode to
// exactly one id. Handlers typically map it to 404 (not 400) so a bad id is
// indistinguishable from a missing row.
var ErrInvalidID = errors.New("invalid id")

type Hasher struct {
	sq *sqids.Sqids
}

// New builds a Hasher. alphabet must be a shuffled permutation unique to the
// app (changing it later invalidates every id ever handed out).
func New(alphabet string, minLength uint8) (*Hasher, error) {
	sq, err := sqids.New(sqids.Options{
		Alphabet:  alphabet,
		MinLength: minLength,
	})
	if err != nil {
		return nil, fmt.Errorf("sqid: building encoder: %w", err)
	}
	return &Hasher{sq: sq}, nil
}

// Encode returns the opaque string for id. Negative ids (which never occur
// for a database sequence) encode to "".
func (h *Hasher) Encode(id int64) string {
	if id < 0 {
		return ""
	}
	s, _ := h.sq.Encode([]uint64{uint64(id)})
	return s
}

// Decode reverses Encode. It also rejects non-canonical strings (a different
// string that happens to decode to the same number), so each id has exactly
// one valid encoding.
func (h *Hasher) Decode(s string) (int64, error) {
	nums := h.sq.Decode(s)
	if len(nums) != 1 || nums[0] > uint64(1<<63-1) {
		return 0, ErrInvalidID
	}
	if canonical, _ := h.sq.Encode(nums); canonical != s {
		return 0, ErrInvalidID
	}
	return int64(nums[0]), nil
}
