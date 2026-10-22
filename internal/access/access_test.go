package access

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for in, want := range map[string]Level{"": Read, "read": Read, "exec": Exec, "create": Create} {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Fatalf("%q: %v %v", in, got, err)
		}
	}
	if _, err := Parse("write"); err == nil {
		t.Fatal("niveau inconnu accepté")
	}
	if !Create.Allows(Exec) || Exec.Allows(Create) || !Read.Allows(Read) || Read.Allows(Exec) {
		t.Fatal("ordre des niveaux")
	}
}

func TestCommands(t *testing.T) {
	c, err := CompileCommands(Rules{Allow: []string{"php -v", "rpm -q *", "java -vers?on", "ls **"}, Deny: []string{"ls -R **"}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		argv []string
		want Decision
	}{
		{[]string{"php", "-v"}, Allowed},
		{[]string{"php", "-v", "x"}, Ask},
		{[]string{"php"}, Ask},
		{[]string{"rpm", "-q", "openssl-libs"}, Allowed},
		{[]string{"rpm", "-q", "a", "b"}, Ask},
		{[]string{"rpm", "-q", "/etc/x"}, Allowed},
		{[]string{"java", "-version"}, Allowed},
		{[]string{"ls"}, Allowed},
		{[]string{"ls", "-l", "/tmp"}, Allowed},
		{[]string{"ls", "-R", "/"}, Denied},
		{[]string{"php", "-r", "system('id');"}, Ask},
	}
	for _, tc := range cases {
		if got := c.Check(tc.argv); got != tc.want {
			t.Fatalf("%v: %v, attendu %v", tc.argv, got, tc.want)
		}
	}
	var nilC *Commands
	if nilC.Check([]string{"php", "-v"}) != Ask {
		t.Fatal("sans règles : confirmation attendue")
	}
	ext, err := c.Extend(Rules{Allow: []string{"openssl version"}, Deny: []string{"php -v"}})
	if err != nil || ext.Check([]string{"openssl", "version"}) != Allowed || ext.Check([]string{"php", "-v"}) != Denied {
		t.Fatalf("extension: %v", err)
	}
	for _, bad := range []string{"", "**", "a ** b", "a\nb"} {
		if _, err := CompileCommands(Rules{Allow: []string{bad}}); err == nil {
			t.Fatalf("motif %q accepté", bad)
		}
	}
}

func TestArgv(t *testing.T) {
	if CheckArgv(nil) == nil || CheckArgv([]string{""}) == nil || CheckArgv([]string{"a", "b\nc"}) == nil {
		t.Fatal("argv invalide accepté")
	}
	if err := CheckArgv([]string{"php", "-v"}); err != nil {
		t.Fatal(err)
	}
	if got := Display([]string{"sh", "-c", "id; ls", "it's"}); got != `sh -c 'id; ls' 'it'"'"'s'` {
		t.Fatal(got)
	}
	for in, want := range map[string]Answer{"o": Once, "Yes": Once, "t": Always, "always": Always, "": No, "n": No, "nope": No} {
		if ParseAnswer(in) != want {
			t.Fatalf("%q", in)
		}
	}
	if !strings.Contains(Exec.String(), "exec") {
		t.Fatal(Exec.String())
	}
}
