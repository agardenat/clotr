package netx

import "testing"

func TestProxyURL(t *testing.T) {
	cases := map[[2]string]string{
		{"socks5h://localhost:1080", "0"}: "socks5h://localhost:1080",
		{"socks5h://127.0.0.1", "1080"}:   "socks5h://127.0.0.1:1080",
		{"localhost:1080/", "0"}:          "socks5h://localhost:1080",
		{"bastion", "1080"}:               "socks5h://bastion:1080",
	}
	for in, want := range cases {
		port := 0
		if in[1] == "1080" {
			port = 1080
		}
		u, err := ProxyURL(in[0], port)
		if err != nil || u.String() != want {
			t.Errorf("%v: %v %v, attendu %s", in, u, err, want)
		}
	}
	if u, err := ProxyURL("", 0); u != nil || err != nil {
		t.Errorf("proxy vide: %v %v", u, err)
	}
	for _, bad := range []string{"socks5h://host", "ftp://host:21"} {
		if _, err := ProxyURL(bad, 0); err == nil {
			t.Errorf("%s accepté", bad)
		}
	}
}
