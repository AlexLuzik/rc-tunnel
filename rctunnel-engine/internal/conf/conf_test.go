package conf

import "testing"

func TestParseFlat(t *testing.T) {
	src := []byte(`
# rctd config
control: ":7000"
work: ":7001"
vhost: "127.0.0.1:8090"   # behind caddy
stats: 127.0.0.1:7401
token: "AB8z_secret"
cert: /p/server.crt
`)
	m := ParseFlat(src)
	cases := map[string]string{
		"control": ":7000", "work": ":7001", "vhost": "127.0.0.1:8090",
		"stats": "127.0.0.1:7401", "token": "AB8z_secret", "cert": "/p/server.crt",
	}
	for k, want := range cases {
		if m[k] != want {
			t.Fatalf("%s: got %q want %q", k, m[k], want)
		}
	}
}
