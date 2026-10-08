package links

import "testing"

const id = "fd54ec88-0239-4868-8dc6-48d8e5979133"

func TestParseSecret(t *testing.T) {
	cases := []struct {
		in   string
		want Secret
	}{
		{"https://h.example/s/" + id + "#abc", Secret{"https://h.example", id, "abc"}},
		{"https://h.example/secret/" + id + "#decryptionKey=abc", Secret{"https://h.example", id, "abc"}},
		{"http://localhost:5173/secret/" + id, Secret{"http://localhost:5173", id, ""}},
		{"https://h.example/prefix/s/" + id + "#k", Secret{"https://h.example/prefix", id, "k"}},
		{id, Secret{"", id, ""}},
		{"https://h.example/s/3uSXycrFyYfP#k", Secret{"https://h.example", "3uSXycrFyYfP", "k"}},
		{"https://h.example/@acme/s/3uSXycrFyYfP#k", Secret{"https://h.example", "3uSXycrFyYfP", "k"}},
		{"https://h.example/prefix/@acme/s/3uSXycrFyYfP", Secret{"https://h.example/prefix", "3uSXycrFyYfP", ""}},
		{"3uSXycrFyYfP", Secret{"", "3uSXycrFyYfP", ""}},
	}
	for _, c := range cases {
		got, err := ParseSecret(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("%s: got %+v, want %+v", c.in, got, c.want)
		}
	}

	for _, bad := range []string{"", "hello", "https://h.example/other/" + id, "https://h.example/s/short", "https://h.example/s/bad%20id1234"} {
		if _, err := ParseSecret(bad); err == nil {
			t.Fatalf("%q must fail", bad)
		}
	}
}

func TestBuildLinks(t *testing.T) {
	if got := SecretLink("https://h.example/", id, "k"); got != "https://h.example/s/"+id+"#k" {
		t.Fatal(got)
	}
	if got := SecretLink("https://h.example", id, ""); got != "https://h.example/s/"+id {
		t.Fatal(got)
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	got, err := NormalizeBaseURL("https://h.example/")
	if err != nil || got != "https://h.example" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := NormalizeBaseURL("h.example"); err == nil {
		t.Fatal("a URL without a scheme must fail")
	}
}
