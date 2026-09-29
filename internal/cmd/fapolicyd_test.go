package cmd

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// newFapolicydForTest wires a FapolicydRunner to fakes with the canonical
// install layout. Each test mutates fields it cares about.
func newFapolicydForTest() (*FapolicydRunner, *FakeExecRunner, *FakeFileSystem, *FakeSystemdRunner, *bytes.Buffer) {
	exec := &FakeExecRunner{Results: map[string]FakeExecResult{}}
	fs := NewFakeFileSystem()
	sysd := &FakeSystemdRunner{ActiveServices: map[string]bool{}}
	out := &bytes.Buffer{}
	r := &FapolicydRunner{
		Exec:    exec,
		FS:      fs,
		Systemd: sysd,
		Out:     out,
	}
	return r, exec, fs, sysd, out
}

func TestFapolicyd_Add_TrustsNodeBinaryWhenPresent(t *testing.T) {
	r, exec, fs, _, _ := newFapolicydForTest()
	fs.Files["/usr/share/heimdall-server/node"] = []byte("")

	err := r.Add()

	require.NoError(t, err)

	var sawNodeAdd bool
	for _, c := range exec.Calls {
		if c.Name == "fapolicyd-cli" &&
			contains(c.Args, "--file") &&
			contains(c.Args, "add") &&
			contains(c.Args, "/usr/share/heimdall-server/node") &&
			contains(c.Args, "--trust-file") &&
			contains(c.Args, "heimdall-server.pending") {
			sawNodeAdd = true
		}
	}
	require.True(t, sawNodeAdd,
		"must invoke fapolicyd-cli --file add for the node binary with --trust-file heimdall-server; calls: %+v",
		exec.Calls)
}

func TestFapolicyd_Add_SkipsNodeBinaryWhenMissing(t *testing.T) {
	r, exec, _, _, _ := newFapolicydForTest()
	// fs is empty — no node binary

	err := r.Add()

	require.NoError(t, err)

	for _, c := range exec.Calls {
		require.NotContains(t, c.Args, "/usr/share/heimdall-server/node",
			"must not try to trust missing node binary")
	}
}

func TestFapolicyd_Add_TrustsNativeAddons(t *testing.T) {
	r, exec, fs, _, _ := newFapolicydForTest()
	addons := []string{
		"/usr/share/heimdall-server/node_modules/argon2/lib/binding/napi-v3/argon2.node",
		"/usr/share/heimdall-server/node_modules/bcrypt/lib/binding/napi-v3/bcrypt_lib.node",
		"/usr/share/heimdall-server/apps/backend/node_modules/sharp/build/Release/sharp.node",
	}
	for _, p := range addons {
		fs.Files[p] = []byte("")
	}

	err := r.Add()

	require.NoError(t, err)

	for _, addon := range addons {
		var sawAdd bool
		for _, c := range exec.Calls {
			if c.Name == "fapolicyd-cli" && contains(c.Args, addon) {
				sawAdd = true
				break
			}
		}
		require.True(t, sawAdd,
			"each .node addon must be trusted; missing: %s", addon)
	}
}

func TestFapolicyd_Add_ReloadsServiceWhenActive(t *testing.T) {
	r, exec, _, sysd, _ := newFapolicydForTest()
	sysd.ActiveServices["fapolicyd"] = true

	err := r.Add()
	require.NoError(t, err)

	var sawUpdate bool
	for _, c := range exec.Calls {
		if c.Name == "fapolicyd-cli" && contains(c.Args, "--update") {
			sawUpdate = true
			break
		}
	}
	require.True(t, sawUpdate,
		"fapolicyd-cli --update must be invoked when fapolicyd service is active")
}

func TestFapolicyd_Add_SkipsReloadWhenServiceInactive(t *testing.T) {
	r, exec, _, _, _ := newFapolicydForTest()
	// fapolicyd inactive (default)

	err := r.Add()
	require.NoError(t, err)

	for _, c := range exec.Calls {
		require.NotContains(t, c.Args, "--update",
			"must not invoke --update when fapolicyd service is inactive")
	}
}

func TestFapolicyd_Remove_DeletesTrustFile(t *testing.T) {
	r, _, fs, _, _ := newFapolicydForTest()
	trustPath := "/etc/fapolicyd/trust.d/heimdall-server"
	fs.Files[trustPath] = []byte("/usr/share/heimdall-server/node\n")

	err := r.Remove()
	require.NoError(t, err)

	require.False(t, fs.Exists(trustPath),
		"trust file must be removed after Remove()")
}

func TestFapolicyd_Remove_TolerantToMissingTrustFile(t *testing.T) {
	r, _, _, _, _ := newFapolicydForTest()
	// no trust file in fs

	err := r.Remove()
	require.NoError(t, err,
		"Remove() must not error when trust file is already absent")
}

func TestFapolicyd_Remove_ReloadsServiceWhenActive(t *testing.T) {
	r, exec, _, sysd, _ := newFapolicydForTest()
	sysd.ActiveServices["fapolicyd"] = true

	err := r.Remove()
	require.NoError(t, err)

	var sawUpdate bool
	for _, c := range exec.Calls {
		if c.Name == "fapolicyd-cli" && contains(c.Args, "--update") {
			sawUpdate = true
			break
		}
	}
	require.True(t, sawUpdate,
		"fapolicyd-cli --update must be invoked when fapolicyd service is active")
}

// --- Cobra-level command surface tests ---

func TestFapolicydCmd_Help(t *testing.T) {
	cmd := NewFapolicydCmd(nil)
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetArgs([]string{"--help"})

	err := cmd.Execute()
	require.NoError(t, err)

	help := out.String()
	require.Contains(t, help, "fapolicyd")
	require.Contains(t, help, "add")
	require.Contains(t, help, "remove")
}

func TestFapolicydCmd_Add_InvokesRunner(t *testing.T) {
	r, exec, fs, _, _ := newFapolicydForTest()
	fs.Files["/usr/share/heimdall-server/node"] = []byte("")
	cmd := NewFapolicydCmd(r)
	cmd.SetArgs([]string{"add"})

	out := &bytes.Buffer{}
	cmd.SetOut(out)

	err := cmd.Execute()
	require.NoError(t, err)
	require.NotEmpty(t, exec.Calls,
		"add subcommand must invoke fapolicyd-cli")
	require.Contains(t, out.String(), "trust entries added")
}

func TestFapolicydCmd_Remove_InvokesRunner(t *testing.T) {
	r, _, fs, _, _ := newFapolicydForTest()
	fs.Files["/etc/fapolicyd/trust.d/heimdall-server"] = []byte("x")
	cmd := NewFapolicydCmd(r)
	cmd.SetArgs([]string{"remove"})

	out := &bytes.Buffer{}
	cmd.SetOut(out)

	err := cmd.Execute()
	require.NoError(t, err)
	require.False(t, fs.Exists("/etc/fapolicyd/trust.d/heimdall-server"),
		"remove subcommand must delete the trust file")
	require.Contains(t, out.String(), "trust entries removed")
}

// contains is a tiny helper for asserting on flag/arg slices.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// avoid `fmt imported but not used` if helpers above stop using it.
var _ = fmt.Sprintf

func TestFapolicyd_PrivateRuntimeAndErrors(t *testing.T) {
	r, exec, fs, _, _ := newFapolicydForTest()
	paths := []string{"/usr/libexec/heimdall-server/runtime/node/bin/node", "/usr/libexec/heimdall-server/runtime/postgresql/bin/postgres", "/usr/libexec/heimdall-server/runtime/postgresql/lib/libpq.so.5", "/usr/libexec/heimdall-server/runtime/caddy/caddy", "/usr/share/heimdall-server/node_modules/argon2.node"}
	for _, p := range paths {
		fs.Files[p] = nil
	}
	fs.Files["/var/lib/heimdall-caddy/unsafe.node"] = nil
	require.NoError(t, r.Add())
	for _, p := range paths {
		seen := false
		for _, c := range exec.Calls {
			if contains(c.Args, p) {
				seen = true
			}
		}
		require.True(t, seen, "missing trust: %s", p)
	}
	for _, c := range exec.Calls {
		require.NotContains(t, c.Args, "/var/lib/heimdall-caddy/unsafe.node")
	}
	exec.Results["fapolicyd-cli --file add"] = FakeExecResult{ExitCode: 1, Stdout: "hash failed"}
	require.Error(t, r.Add(), "real trust failures must not report success")
}

func TestFapolicydRefreshPreservesTrustOnFailureAndSkipsAliases(t *testing.T) {
	r, exec, fs, sysd, out := newFapolicydForTest()
	path := "/usr/libexec/heimdall-server/runtime/postgresql/lib/libpq.so.5.18"
	fs.Files[path] = nil
	trust := "/etc/fapolicyd/trust.d/heimdall-server"
	fs.Files[trust] = []byte("old hash\n")
	fs.Files["/etc/fapolicyd/trust.d/operator"] = []byte("untouched\n")
	exec.Results["fapolicyd-cli --file add"] = FakeExecResult{ExitCode: 1}
	require.Error(t, r.Add())
	require.Equal(t, "old hash\n", string(fs.Files[trust]))
	require.NotContains(t, out.String(), "trust entries added")
	delete(exec.Results, "fapolicyd-cli --file add")
	sysd.ActiveServices["fapolicyd"] = true
	exec.Results["fapolicyd-cli --update"] = FakeExecResult{ExitCode: 1}
	require.Error(t, r.Add())
	require.NoError(t, fs.RemoveAll(path))
	delete(exec.Results, "fapolicyd-cli --update")
	require.NoError(t, r.Remove())
	require.Equal(t, "untouched\n", string(fs.Files["/etc/fapolicyd/trust.d/operator"]))
}
func TestFapolicydMissingVersusBrokenTool(t *testing.T) {
	for _, code := range []int{1, 127} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			r, exec, fs, _, out := newFapolicydForTest()
			fs.Files["/usr/share/heimdall-server/argon.node"] = nil
			exec.Results[`sh -c command -v "$1" sh fapolicyd-cli`] = FakeExecResult{ExitCode: code}
			err := r.Add()
			if code == 1 {
				require.NoError(t, err)
				require.Contains(t, out.String(), "not installed")
			} else {
				require.Error(t, err)
			}
			require.NotContains(t, out.String(), "trust entries added")
			for _, c := range exec.Calls {
				require.NotEqual(t, "fapolicyd-cli", c.Name)
			}
		})
	}
}

func TestFapolicydRefusesLinkedAddonAndTrustRoot(t *testing.T) {
	for _, path := range []string{"/usr/share/heimdall-server/native.node", "/usr/libexec/heimdall-server/runtime/postgresql/lib"} {
		t.Run(path, func(t *testing.T) {
			r, _, fs, _, _ := newFapolicydForTest()
			fs.Files[path] = nil
			r.FS = &securityFS{FakeFileSystem: fs, badPath: path, badMode: os.ModeSymlink | 0777}
			require.Error(t, r.Add())
		})
	}
}
