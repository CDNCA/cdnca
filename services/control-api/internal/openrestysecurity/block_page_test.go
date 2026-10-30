package openrestysecurity

import "testing"

// FX60：拉黑/拦截页是否计入流量。缺省（未保存过全局配置、字段缺失）默认“不计入”。
func TestBlockPageNotCountedFromDocument(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
		want bool
	}{
		{"no global row", nil, true},
		{"explicit false", []byte(`{"block_page_not_counted":false}`), false},
		{"explicit true", []byte(`{"block_page_not_counted":true}`), true},
		{"field absent", []byte(`{"cc_enable":true}`), true},
		{"malformed value keeps default", []byte(`{"block_page_not_counted":"no"}`), true},
	} {
		if got := blockPageNotCountedFromDocument(test.raw); got != test.want {
			t.Errorf("%s: got %v want %v", test.name, got, test.want)
		}
	}
	if !DefaultBlockPageNotCounted() {
		t.Fatal("default must exclude block pages")
	}
}
