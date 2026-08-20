package qemu

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// The package the image builds must exist and compile.
//
// `go build ./...` reports success on a tree with NO main package, because there is nothing there
// to fail. That is how commit 23b3fea deleted cmd/tinq/main.go, claimed in its message to have left
// a four-line shim, and pushed a branch whose own Dockerfile could not build it -- with every test
// green. The already-published image meant nothing tried until a rebuild was needed.
//
// This asserts the path the Dockerfile names, read FROM the Dockerfile rather than repeated here, so
// moving the entrypoint updates one place and this test follows it.
func TestImageEntrypointBuilds(t *testing.T) {
	df, err := os.ReadFile("../Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	m := regexp.MustCompile(`go build[^\n]*\s(\./\S+)\s*$`).FindSubmatch(
		[]byte(firstBuildLine(t, string(df))))
	if m == nil {
		t.Fatal("no `go build ./...` target found in the Dockerfile; this test cannot verify anything")
	}
	pkg := string(m[1])

	build := exec.Command("go", "build", "-o", os.DevNull, pkg)
	build.Dir = ".." // pkg is repo-root-relative, as the Dockerfile's WORKDIR makes it
	out, err := build.CombinedOutput()
	if err != nil {
		t.Fatalf("the Dockerfile builds %s and it does not compile:\n%s", pkg, out)
	}
}

func firstBuildLine(t *testing.T, dockerfile string) string {
	t.Helper()
	for _, l := range strings.Split(dockerfile, "\n") {
		if strings.Contains(l, "go build") {
			return l
		}
	}
	t.Fatal("the Dockerfile has no `go build` line; this test cannot verify anything")
	return ""
}
