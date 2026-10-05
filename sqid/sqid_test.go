package sqid

import (
	"errors"
	"testing"
)

const alphabet = "k3G7QAe51FCsPW92uEOyq4Bg6Sp8YzVTmnU0liwDdHXLajZrfxNhobJIRcMvKt"

func TestRoundTrip(t *testing.T) {
	h, err := New(alphabet, 6)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{0, 1, 42, 1 << 40} {
		s := h.Encode(id)
		if len(s) < 6 {
			t.Errorf("Encode(%d) = %q, shorter than minLength", id, s)
		}
		got, err := h.Decode(s)
		if err != nil || got != id {
			t.Errorf("Decode(Encode(%d)) = %d, %v", id, got, err)
		}
	}
	if h.Encode(-1) != "" {
		t.Error("negative id should encode to empty string")
	}
}

func TestDecodeRejects(t *testing.T) {
	h, _ := New(alphabet, 6)
	multi, _ := h.sq.Encode([]uint64{1, 2})
	for _, s := range []string{"", "!!!", multi} {
		if _, err := h.Decode(s); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Decode(%q) err = %v, want ErrInvalidID", s, err)
		}
	}
}

func TestNewRejectsBadAlphabet(t *testing.T) {
	if _, err := New("aab", 0); err == nil {
		t.Error("duplicate-character alphabet: want error")
	}
}
