package browser

import (
	"path/filepath"
	"testing"
)

// ═══════════════════════════════════════════════════════════
// Unit Tests: Session Name Sanitization & File Path
// ═══════════════════════════════════════════════════════════

func TestSanitizeSessionName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"clean name", "user_a", "user_a"},
		{"with dots", "user.admin", "user_admin"},
		{"path traversal", "../../etc/passwd", "______etc_passwd"},
		{"backslash traversal", `..\..\windows`, `______windows`},
		{"null byte", "user\x00admin", "user_admin"},
		{"slashes", "dir/subdir/name", "dir_subdir_name"},
		{"empty string", "", ""},
		{"just dots", "..", "__"},
		{"mixed dangerous", "../../../tmp/evil.json", "_________tmp_evil_json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeSessionName(tt.input)
			if got != tt.expected {
				t.Errorf("sanitizeSessionName(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestSessionFilePath(t *testing.T) {
	dir := "/tmp/sessions"

	tests := []struct {
		name     string
		dir      string
		sessName string
		expected string
	}{
		{"empty dir returns empty", "", "user_a", ""},
		{"default name", dir, "default", filepath.Join(dir, "session.json")},
		{"empty name is default", dir, "", filepath.Join(dir, "session.json")},
		{"named session", dir, "user_a", filepath.Join(dir, "user_a_session.json")},
		{"sanitizes traversal", dir, "../../etc/evil", filepath.Join(dir, "______etc_evil_session.json")},
		{"sanitizes dots", dir, "admin.user", filepath.Join(dir, "admin_user_session.json")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sessionFilePath(tt.dir, tt.sessName)
			if got != tt.expected {
				t.Errorf("sessionFilePath(%q, %q) = %q, want %q", tt.dir, tt.sessName, got, tt.expected)
			}
		})
	}
}
