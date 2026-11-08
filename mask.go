package secure

import (
	"strings"
)

// MaskEmail masks an email address for logging/display purposes.
// Shows only the first Unicode code point of the local part and the full domain.
//
// Examples:
//   - "user@example.com" -> "u***@example.com"
//   - "test.user@example.com" -> "t********@example.com"
//   - "a@example.com" -> "a***@example.com"
func MaskEmail(email string) string {
	if email == "" {
		return ""
	}

	email = strings.TrimSpace(email)
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		// Invalid email format, mask everything
		return "***@***"
	}

	localPart := parts[0]
	domain := parts[1]

	// If local part is empty, mask it
	if localPart == "" {
		return "***@" + domain
	}

	// Show first character and mask the rest
	localRunes := []rune(localPart)
	if len(localRunes) == 1 {
		return localPart + "***@" + domain
	}

	return string(localRunes[:1]) + strings.Repeat("*", len(localRunes)-1) + "@" + domain
}

// MaskEmailPartial masks an email address, showing its first 2 Unicode code points.
// This provides slightly more context while still protecting privacy.
//
// Examples:
//   - "john.doe@example.com" -> "jo***@example.com"
//   - "user@example.com" -> "us***@example.com"
func MaskEmailPartial(email string) string {
	if email == "" {
		return ""
	}

	email = strings.TrimSpace(email)
	atIndex := strings.Index(email, "@")
	if atIndex <= 0 {
		return "***"
	}

	localPart := email[:atIndex]
	domain := email[atIndex:]

	localRunes := []rune(localPart)
	if len(localRunes) <= 2 {
		return localPart + "***" + domain
	}
	return string(localRunes[:2]) + "***" + domain
}

// MaskPhone masks a phone number for logging/display purposes.
// Shows only the first 3 and last 4 Unicode code points. Numeric ASCII formats
// retain their existing output.
//
// Examples:
//   - "13812345678" -> "138****5678"
//   - "+8613812345678" -> "+86*******5678"
//   - "1234567" -> "123****"
func MaskPhone(phone string) string {
	if phone == "" {
		return ""
	}

	phone = strings.TrimSpace(phone)
	runes := []rune(phone)
	length := len(runes)

	// If phone is too short, mask everything
	if length < 7 {
		return "****"
	}

	// Show first 3 and last 4 digits
	if length <= 7 {
		return string(runes[:3]) + "****"
	}

	return string(runes[:3]) + strings.Repeat("*", length-7) + string(runes[length-4:])
}

// MaskPhoneSimple masks a phone number with a simpler format.
// Shows first 3 and last 4 Unicode code points with fixed *** in between.
//
// Examples:
//   - "+1234567890" -> "+12***7890"
//   - "13812345678" -> "138***5678"
func MaskPhoneSimple(phone string) string {
	runes := []rune(phone)
	if len(runes) <= 6 {
		return "***"
	}
	return string(runes[:3]) + "***" + string(runes[len(runes)-4:])
}

// MaskString masks a string, showing visibleChars Unicode code points at each end.
// visibleChars must be non-negative; if negative, returns "***" without panicking.
//
// Examples (with visibleChars=3):
//   - "1234567890" -> "123***890"
//   - "short" -> "***"
func MaskString(s string, visibleChars int) string {
	if visibleChars < 0 {
		return "***"
	}
	runes := []rune(s)
	// Avoid multiplying caller-supplied bounds, which can overflow int.
	if visibleChars >= len(runes) || visibleChars >= len(runes)-visibleChars {
		return "***"
	}
	return string(runes[:visibleChars]) + "***" + string(runes[len(runes)-visibleChars:])
}

// MaskCreditCard masks a credit card number, showing only the last 4 Unicode
// code points after removing ASCII spaces and dashes.
//
// Examples:
//   - "4111111111111111" -> "************1111"
//   - "4111-1111-1111-1111" -> "****-****-****-1111"
func MaskCreditCard(card string) string {
	if card == "" {
		return ""
	}

	// Remove spaces and dashes for processing
	cleaned := strings.ReplaceAll(strings.ReplaceAll(card, " ", ""), "-", "")

	runes := []rune(cleaned)
	if len(runes) < 4 {
		return "****"
	}

	// Get last 4 digits
	last4 := string(runes[len(runes)-4:])

	// If the original had dashes (typical format), preserve that
	if strings.Contains(card, "-") {
		return "****-****-****-" + last4
	}

	// Otherwise, mask with asterisks
	return strings.Repeat("*", len(runes)-4) + last4
}

// MaskIPAddress masks an IP address for logging/display purposes.
// For IPv4, shows only the first octet.
// For IPv6, shows only the first segment.
//
// Examples:
//   - "192.168.1.100" -> "192.*.*.*"
//   - "2001:0db8:85a3:0000:0000:8a2e:0370:7334" -> "2001:****:****:****:****:****:****:****"
func MaskIPAddress(ip string) string {
	if ip == "" {
		return ""
	}

	// Check if it's IPv6 (contains ":")
	// Note: strings.Split on ":" always returns at least 2 elements if ":" exists
	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		return parts[0] + ":****:****:****:****:****:****:****"
	}

	// IPv4
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return parts[0] + ".*.*.*"
	}

	return "****"
}

// MaskAPIKey masks an API key, showing its first and last 4 Unicode code points.
//
// Examples:
//   - "sk_live_abcdefghijklmnop" -> "sk_l***mnop"
//   - "key_1234567890" -> "key_***7890"
func MaskAPIKey(key string) string {
	runes := []rune(key)
	if len(runes) <= 8 {
		return "***"
	}
	return string(runes[:4]) + "***" + string(runes[len(runes)-4:])
}

// MaskName masks a person's name for privacy.
// Shows only the first Unicode code point of each whitespace-separated word.
//
// Examples:
//   - "John Doe" -> "J*** D***"
//   - "Alice" -> "A***"
func MaskName(name string) string {
	if name == "" {
		return ""
	}

	words := strings.Fields(name)
	masked := make([]string, len(words))

	for i, word := range words {
		if len(word) > 0 {
			masked[i] = string([]rune(word)[:1]) + "***"
		}
	}

	return strings.Join(masked, " ")
}

// TruncateString truncates a string to maxLen Unicode code points.
// A code point is a rune, not a byte or a complete grapheme cluster.
// Adds "..." suffix if truncated.
func TruncateString(s string, maxLen int) string {
	if maxLen < 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
