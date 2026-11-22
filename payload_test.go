package sign

import "testing"

func TestIsSimpleSigningPayload(t *testing.T) {
	p, err := SimpleSigningPayload("example.com/img", "sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		in   []byte
		want bool
	}{
		{"payload", p, true},
		{"other type", []byte(`{"critical":{"type":"x"}}`), false},
		{"no critical", []byte(`{"optional":null}`), false},
		{"not json", []byte("raw bytes"), false},
		{"json array", []byte(`[1]`), false},
		{"empty", nil, false},
	} {
		if got := IsSimpleSigningPayload(c.in); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
