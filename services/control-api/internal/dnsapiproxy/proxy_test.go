package dnsapiproxy

import "testing"

func TestValid(t *testing.T) {
	for _, raw := range []string{
		"", "http://proxy.example:3128", "https://proxy.example", "http://10.0.0.1:8080/",
		"http://[2001:db8::1]:3128", "HTTP://Proxy.Example:3128", "http://ops:s%40cret@proxy.example:3128",
		"http://ops@proxy.example:3128",
	} {
		if !Valid(raw) {
			t.Errorf("Valid(%q) = false", raw)
		}
	}
	for _, raw := range []string{
		"proxy.example:3128", "socks5://proxy.example:1080", "ftp://proxy.example", "http://", "http://:3128",
		"http://proxy.example:", "http://proxy.example:0", "http://proxy.example:65536", "http://proxy.example:80a",
		"http://proxy.example/path", "http://proxy.example?x=1", "http://proxy.example#x", "http://proxy.example/?",
		"http://pro xy.example", "http://proxy.example:3128\n", "http://-bad.example", "http://bad_host.example",
		"http://[fe80::1%25en0]:3128", "http://:pass@proxy.example", "http:proxy.example",
	} {
		if Valid(raw) {
			t.Errorf("Valid(%q) = true", raw)
		}
	}
}

func TestRedactAndRestore(t *testing.T) {
	stored := "http://ops:s3cret@proxy.example:3128"
	shown := Redact(stored)
	if shown != "http://ops:********@proxy.example:3128" {
		t.Fatalf("Redact = %q", shown)
	}
	for _, raw := range []string{"", "http://proxy.example:3128", "http://ops@proxy.example:3128"} {
		if Redact(raw) != raw {
			t.Errorf("Redact(%q) = %q", raw, Redact(raw))
		}
	}
	if restored, ok := Restore(shown, stored); !ok || restored != stored {
		t.Fatalf("Restore(shown) = (%q,%v)", restored, ok)
	}
	if restored, ok := Restore("http://ops:n3w@proxy.example:3128", stored); !ok || restored != "http://ops:n3w@proxy.example:3128" {
		t.Fatalf("Restore(new password) = (%q,%v)", restored, ok)
	}
	for _, incoming := range []string{
		"http://ops:********@other.example:3128", "http://root:********@proxy.example:3128",
		"https://ops:********@proxy.example:3128", "http://ops:********@proxy.example:3129",
	} {
		if _, ok := Restore(incoming, stored); ok {
			t.Errorf("Restore(%q) accepted a mask for another proxy", incoming)
		}
	}
	if _, ok := Restore(shown, ""); ok {
		t.Fatal("Restore accepted a mask with nothing stored")
	}
}
