package snapshot

import "testing"

// The forms edge-analyst src/blocklist.js pathForms gives for the same inputs (contracts §D3 "Path matching").
func TestPathFormsMatchTheReference(t *testing.T) {
	cases := map[string][3]string{
		"/":                      {"/", "/", "/"},
		"/%62locked-path":        {"/%62locked-path", "/blocked-path", "/blocked-path"},
		"/BLOCKED-PATH/":         {"/BLOCKED-PATH/", "/blocked-path", "/blocked-path"},
		"//a//b/":                {"//a//b/", "/a/b", "/a/b"},
		"/x/%2e%2E/y":            {"/x/%2e%2E/y", "/x/../y", "/y"},
		"/..;/admin":             {"/..;/admin", "/../admin", "/admin"},
		"/a%2Fb":                 {"/a%2Fb", "/a%2fb", "/a%2fb"},
		"/café":                  {"/café", "/caf%c3%a9", "/caf%c3%a9"},
		"/a b":                   {"/a b", "/a%20b", "/a%20b"},
		"/%zz":                   {"/%zz", "/%25zz", "/%25zz"},
		"/a#b?c":                 {"/a", "/a", "/a"},
		"/..":                    {"/..", "/..", "/"},
		"/locked/public/../../x": {"/locked/public/../../x", "/locked/public/../../x", "/x"},
	}
	for in, want := range cases {
		if got := PathForms(in); got != want {
			t.Errorf("PathForms(%q) = %q, want %q", in, got, want)
		}
	}
}
