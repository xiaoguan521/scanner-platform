package scope

import "testing"

// FuzzParseEndpoint has no network side effects.
func FuzzParseEndpoint(f *testing.F) {
	for _, s := range []string{"192.0.2.10:443", "198.51.100.5:80", "[2001:db8::1]:443", "example.com:443", "192.0.2.0/24:443", "192.0.2.1:0", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		endpoint, err := ParseEndpoint(s)
		if err != nil {
			return
		}
		again, err := ParseEndpoint(endpoint.String())
		if err != nil || again != endpoint {
			t.Fatalf("round-trip invalid: %q, %v", s, err)
		}
	})
}
