package version

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion(t *testing.T) {
	t.Run("VERSION not specified", func(t *testing.T) {
		expected := fmt.Sprintf(
			"\n\tNot specify ldflags (which link version) during go build\n\tgo version: %s %s/%s",
			runtime.Version(),
			runtime.GOOS,
			runtime.GOARCH)
		assert.Equal(t, expected, GetVersion())
	})

	t.Run("VERSION constly specified", func(t *testing.T) {
		VERSION = "Release-v3.100.200"
		BUILD_TIME = "2020-09-11T07:05:04Z"
		COMMIT_HASH = "fb2481c2"
		COMMIT_TIME = "2020-09-11T07:00:29Z"

		expected := fmt.Sprintf(
			"\n\tfree5GC version: %s"+
				"\n\tbuild time:      %s"+
				"\n\tcommit hash:     %s"+
				"\n\tcommit time:     %s"+
				"\n\tgo version:      %s %s/%s",
			VERSION,
			BUILD_TIME,
			COMMIT_HASH,
			COMMIT_TIME,
			runtime.Version(),
			runtime.GOOS,
			runtime.GOARCH)

		assert.Equal(t, expected, GetVersion())
		fmt.Println(VERSION)
	})

	t.Run("VERSION capture by system", func(t *testing.T) {
		var stdout []byte
		var err error
		VERSION = "Release-v3.100.200" // VERSION using free5gc's version (git tag), we static set it here
		stdout, err = exec.Command("bash", "-c", "date -u +\"%Y-%m-%dT%H:%M:%SZ\"").Output()
		if err != nil {
			t.Errorf("err: %+v\n", err)
		}
		BUILD_TIME = strings.TrimSuffix(string(stdout), "\n")
		stdout, err = exec.Command("bash", "-c", "git log --pretty=\"%H\" -1 | cut -c1-8").Output()
		if err != nil {
			t.Errorf("err: %+v\n", err)
		}
		COMMIT_HASH = strings.TrimSuffix(string(stdout), "\n")
		stdout, err = exec.Command("bash", "-c",
			"git log --pretty=\"%ai\" -1 | awk '{time=$1\"T\"$2\"Z\"; print time}'").Output()
		if err != nil {
			t.Errorf("err: %+v\n", err)
		}
		fmt.Println("Insert Data")
		COMMIT_TIME = strings.TrimSuffix(string(stdout), "\n")

		expected := fmt.Sprintf(
			"\n\tfree5GC version: %s"+
				"\n\tbuild time:      %s"+
				"\n\tcommit hash:     %s"+
				"\n\tcommit time:     %s"+
				"\n\tgo version:      %s %s/%s",
			VERSION,
			BUILD_TIME,
			COMMIT_HASH,
			COMMIT_TIME,
			runtime.Version(),
			runtime.GOOS,
			runtime.GOARCH)

		assert.Equal(t, expected, GetVersion())
		fmt.Println(VERSION)
	})
}
