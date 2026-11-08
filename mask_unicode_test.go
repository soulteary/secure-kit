package secure

import (
	"math"
	"testing"
	"unicode/utf8"
)

func TestMaskUnicodeCodePoints(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"name", MaskName("张三 李四"), "张*** 李***"},
		{"name emoji", MaskName("😀 Name"), "😀*** N***"},
		{"email", MaskEmail("张三@example.com"), "张*@example.com"},
		{"email single", MaskEmail("张@example.com"), "张***@example.com"},
		{"email partial", MaskEmailPartial("张三李@example.com"), "张三***@example.com"},
		{"email partial short", MaskEmailPartial("张三@example.com"), "张三***@example.com"},
		{"phone", MaskPhone("１２３４５６７８９０１"), "１２３****８９０１"},
		{"phone seven", MaskPhone("１２３４５６７"), "１２３****"},
		{"phone short", MaskPhone("１２３４５６"), "****"},
		{"phone simple", MaskPhoneSimple("１２３４５６７８９０１"), "１２３***８９０１"},
		{"phone simple seven", MaskPhoneSimple("１２３４５６７"), "１２３***４５６７"},
		{"phone simple short", MaskPhoneSimple("１２３４５６"), "***"},
		{"string", MaskString("张三李四王", 1), "张***王"},
		{"string boundary", MaskString("张三", 1), "***"},
		{"api key", MaskAPIKey("一二三四五六七八九"), "一二三四***六七八九"},
		{"api key short", MaskAPIKey("一二三四五六七八"), "***"},
		{"card", MaskCreditCard("１２３４５６７８"), "****５６７８"},
		{"card formatted", MaskCreditCard("１２３４-５６７８"), "****-****-****-５６７８"},
		{"truncate", TruncateString("很长的文本内容", 4), "很长的文..."},
		{"truncate emoji", TruncateString("😀😃😄", 2), "😀😃..."},
		// A rune is a code point, not a grapheme cluster: the accent is separate.
		{"truncate combining", TruncateString("e\u0301x", 1), "e..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !utf8.ValidString(tt.got) || tt.got != tt.want {
				t.Fatalf("got %q (valid UTF-8: %v), want %q", tt.got, utf8.ValidString(tt.got), tt.want)
			}
		})
	}
}

func TestMaskRuneBounds(t *testing.T) {
	for _, visible := range []int{-1, math.MaxInt / 2, math.MaxInt/2 + 1, math.MaxInt} {
		for _, input := range []string{"", "abcdef", "张三李四"} {
			if got := MaskString(input, visible); got != "***" {
				t.Fatalf("MaskString(%q, %d) = %q", input, visible, got)
			}
		}
	}
	for _, tt := range []struct {
		input string
		limit int
		want  string
	}{
		{"张三", -1, ""}, {"", 0, ""}, {"张三", 0, "..."},
		{"张三", 2, "张三"}, {"张三", math.MaxInt, "张三"},
	} {
		if got := TruncateString(tt.input, tt.limit); got != tt.want {
			t.Fatalf("TruncateString(%q, %d) = %q, want %q", tt.input, tt.limit, got, tt.want)
		}
	}
}
