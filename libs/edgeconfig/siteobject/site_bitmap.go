package siteobject

import (
	"fmt"
	"math/bits"
	"sort"
)

// SiteBitmap is KeyDocument.WithheldSites (SITE_SELECTION v1): bit i (byte
// i/8, bit i%8, least significant first) is set when the node does not serve
// the root's i-th website in ascending site_id order. Sites is the root's
// website count, so the bitmap is ceil(Sites/8) bytes whatever the number
// withheld: 100,000 websites take 12,500 bytes (16,668 in the JSON's base64).
// Unused trailing bits are zero; at least one bit is set (no website
// withheld: the field is omitted).
type SiteBitmap struct {
	Sites  int    `json:"sites"`
	Bitmap []byte `json:"bitmap"`
}

// NewSiteBitmap is the bitmap of siteIDs (the root's websites, any order)
// withholding withheld; nil when withheld is empty.
func NewSiteBitmap(siteIDs []string, withheld map[string]bool) *SiteBitmap {
	if len(withheld) == 0 {
		return nil
	}
	sorted := append([]string(nil), siteIDs...)
	sort.Strings(sorted)
	result := &SiteBitmap{Sites: len(sorted), Bitmap: make([]byte, (len(sorted)+7)/8)}
	for index, id := range sorted {
		if withheld[id] {
			result.Bitmap[index/8] |= 1 << (index % 8)
		}
	}
	return result
}

// Withheld says whether the index-th website (ascending site_id) is withheld.
func (bitmap *SiteBitmap) Withheld(index int) bool {
	return bitmap != nil && index >= 0 && index < bitmap.Sites && bitmap.Bitmap[index/8]&(1<<(index%8)) != 0
}

// Count is the number of withheld websites.
func (bitmap *SiteBitmap) Count() int {
	if bitmap == nil {
		return 0
	}
	count := 0
	for _, value := range bitmap.Bitmap {
		count += bits.OnesCount8(value)
	}
	return count
}

func (bitmap *SiteBitmap) validate() error {
	if bitmap == nil {
		return nil
	}
	if bitmap.Sites < 1 || bitmap.Sites > MaxWithheldSitesBitmapSites || len(bitmap.Bitmap) != (bitmap.Sites+7)/8 {
		return fmt.Errorf("%w: withheld sites bitmap size", ErrInvalid)
	}
	if tail := bitmap.Sites % 8; tail != 0 && bitmap.Bitmap[len(bitmap.Bitmap)-1]>>tail != 0 {
		return fmt.Errorf("%w: withheld sites bitmap trailing bits", ErrInvalid)
	}
	if bitmap.Count() == 0 {
		return fmt.Errorf("%w: withheld sites bitmap withholds none", ErrInvalid)
	}
	return nil
}
