package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Smoke tests for the runtime adapters in runtime.go. These exercise
// the real OS wrappers against portable programs (cat, true, false)
// so we know the thin glue actually works — fakes alone don't catch
// "forgot to set Stdin" / "forgot to capture exit code" mistakes.
//
// Pattern matches stdlib os/exec_test.go (which runs /bin/echo etc.).
// Skipped on Windows where these programs aren't guaranteed.

func skipIfWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("portable Unix utilities (cat/true/false) unavailable on Windows")
	}
}

func TestRealExecRunner_Run_CapturesStdoutAndExitZero(t *testing.T) {
	skipIfWindows(t)

	r := &execRunner{}
	out, code, err := r.Run("echo", "hello")

	require.NoError(t, err)
	require.Equal(t, 0, code)
	require.Equal(t, "hello\n", out)
}

func TestRealExecRunner_Run_CapturesNonZeroExit(t *testing.T) {
	skipIfWindows(t)

	r := &execRunner{}
	_, code, err := r.Run("false")

	require.NoError(t, err, "non-zero exit must not surface as Go error")
	require.NotEqual(t, 0, code, "exit code must reflect failure")
}

func TestRealExecRunner_RunWithStdin_PipesStdin(t *testing.T) {
	skipIfWindows(t)

	r := &execRunner{}
	const payload = "line one\nline two\n"

	out, code, err := r.RunWithStdin(payload, "cat")

	require.NoError(t, err)
	require.Equal(t, 0, code)
	require.Equal(t, payload, out,
		"cat must echo back the stdin payload byte-for-byte")
}

func TestRealExecRunner_RunWithStdin_CapturesNonZeroExit(t *testing.T) {
	skipIfWindows(t)

	r := &execRunner{}
	_, code, err := r.RunWithStdin("ignored", "false")

	require.NoError(t, err)
	require.NotEqual(t, 0, code)
}

func TestRealExecRunner_RunWithEnv_PassesEnv(t *testing.T) {
	skipIfWindows(t)

	r := &execRunner{}
	out, code, err := r.RunWithEnv(
		map[string]string{"GREETING": "hello-from-env"},
		"sh", "-c", "echo $GREETING",
	)

	require.NoError(t, err)
	require.Equal(t, 0, code)
	require.Equal(t, "hello-from-env\n", out)
}

func TestRealOsFileSystem_FindFiles_RecursivelyMatchesByName(t *testing.T) {
	root := t.TempDir()

	// Create a small tree:
	//   root/a.node
	//   root/sub/b.node
	//   root/sub/c.txt   (must NOT match)
	//   root/sub/deep/d.node
	for _, rel := range []string{"a.node", "sub/b.node", "sub/c.txt", "sub/deep/d.node"} {
		full := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte("x"), 0o644))
	}

	fs := &osFileSystem{}
	matches, err := fs.FindFiles(root, "*.node")
	require.NoError(t, err)
	require.Len(t, matches, 3, "must find all three .node files; got %v", matches)

	// Build a set of basenames for order-independent assertion.
	names := map[string]bool{}
	for _, m := range matches {
		names[filepath.Base(m)] = true
	}
	require.True(t, names["a.node"])
	require.True(t, names["b.node"])
	require.True(t, names["d.node"])
	require.False(t, names["c.txt"], "must not match non-.node files")
}

func TestRealOsFileSystem_FindFiles_ReturnsNothingForMissingRoot(t *testing.T) {
	fs := &osFileSystem{}
	matches, err := fs.FindFiles("/nonexistent/path/that/should/not/exist", "*.node")
	require.NoError(t, err, "missing root must not be an error")
	require.Empty(t, matches)
}

func TestRealPSQLConnectorPrivateBinaryAndSSL(t *testing.T) {
	skipIfWindows(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "psql"), []byte("#!/bin/sh\nexit 93\n"), 0755))
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	private := filepath.Join(dir, "private-psql")
	require.NoError(t, os.WriteFile(private, []byte(`#!/bin/sh
[ "$PGPASSWORD" = "new-secret" ] || exit 91
[ "$PGSSLMODE" = "verify-full" ] || exit 92
case "$*" in
 *information_schema*) echo 7 ;;
 *) echo 1 ;;
esac
`), 0755))
	saved := map[string]string{"PGPASSWORD": "old-secret", "PGSSLMODE": "verify-full"}
	db := &psqlConnector{Binary: private, Env: saved}
	require.NoError(t, db.TestConnection("db", 5432, "app", "new-secret", "prod"))
	count, err := db.TableCount("db", 5432, "app", "new-secret", "prod")
	require.NoError(t, err)
	require.Equal(t, 7, count)
	require.Equal(t, "old-secret", saved["PGPASSWORD"])
	db.Binary = filepath.Join(dir, "missing")
	require.Error(t, db.TestConnection("db", 5432, "app", "new-secret", "prod"))
}

func TestRealRPMClientRouting(t *testing.T) {
	skipIfWindows(t)
	dir := t.TempDir()
	paths := DefaultPaths()
	paths.AppDir = filepath.Join(dir, "app")
	paths.LibExecDir = filepath.Join(dir, "libexec")
	paths.EnvFile = filepath.Join(dir, "backend.env")
	require.NoError(t, os.MkdirAll(paths.AppDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(paths.AppDir, "runtime-manifest.json"), []byte(`{}`), 0644))
	privateBin := paths.RuntimePath("postgresql", "bin")
	require.NoError(t, os.MkdirAll(privateBin, 0755))
	ambient := filepath.Join(dir, "ambient")
	require.NoError(t, os.MkdirAll(ambient, 0755))
	for _, name := range []string{"psql", "pg_dump"} {
		require.NoError(t, os.WriteFile(filepath.Join(ambient, name), []byte("#!/bin/sh\nexit 93\n"), 0755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(ambient, "chown"), []byte("#!/bin/sh\nexit 0\n"), 0755))
	t.Setenv("PATH", ambient+":"+os.Getenv("PATH"))
	log := filepath.Join(dir, "calls")
	t.Setenv("HEIMDALL_TEST_CALLS", log)
	script := `#!/bin/sh
[ "$PGPASSWORD" = "secret" ] || exit 91
[ "$PGSSLMODE" = "verify-full" ] || exit 92
[ -r "$PGSSLROOTCERT" ] || exit 94
case "$*" in *secret*) exit 95;; esac
printf '%s\n' "$0" >> "$HEIMDALL_TEST_CALLS"
printf '%s\n' "$PGSSLROOTCERT" >> "$HEIMDALL_TEST_CALLS"
case "$0" in
 *pg_dump)
  while [ "$#" -gt 0 ]; do
   if [ "$1" = "-f" ]; then shift; printf '%s\n' '-- SQL fixture' > "$1"; exit 0; fi
   shift
  done
  exit 96 ;;
esac
case "$*" in
 *information_schema*) echo 7 ;;
 *UPDATE*) echo 'UPDATE 1' ;;
 *) echo 1 ;;
esac
`
	for _, name := range []string{"psql", "pg_dump"} {
		require.NoError(t, os.WriteFile(filepath.Join(privateBin, name), []byte(script), 0755))
	}
	env := &FileEnvManager{Path: paths.EnvFile}
	require.NoError(t, env.WriteEnvFile(map[string]string{"DATABASE_HOST": "localhost", "DATABASE_PORT": "5432", "DATABASE_USERNAME": "app", "DATABASE_NAME": "prod", "DATABASE_PASSWORD": "secret", "JWT_SECRET": "jwt", "DATABASE_SSL": "true", "DATABASE_SSL_INSECURE": "false", "DATABASE_SSL_CA": "-----BEGIN CERTIFICATE-----fixture-----END CERTIFICATE-----", "HEIMDALL_DATABASE_MODE": "external", "HEIMDALL_PROXY_MODE": "external"}))
	output := new(bytes.Buffer)
	fs := &osFileSystem{}
	commands := []struct {
		name, client string
		run          func() error
	}{
		{"setup", "psql", func() error {
			r, _, _ := newTestSetupRunner()
			r.Paths = paths
			r.FS = fs
			r.Env = env
			r.DB = &psqlConnector{}
			_, err := r.readConfiguration()
			if err != nil {
				return err
			}
			return r.stepConnectionTest()
		}},
		{"status", "psql", func() error {
			r, _ := newTestStatusRunner()
			r.Paths = paths
			r.FS = fs
			r.Env = env
			r.DB = &psqlConnector{}
			r.JSON = true
			return r.Run()
		}},
		{"validate", "psql", func() error {
			r := &ValidateRunner{Paths: paths, FS: fs, Env: env, DB: &psqlConnector{}, Out: output}
			return r.Run()
		}},
		{"backup", "pg_dump", func() error {
			r := &BackupRunner{Paths: paths, FS: fs, Env: env, Exec: &execRunner{}, Out: output, ErrOut: output}
			return r.Run(dir)
		}},
		{"restore", "psql", func() error {
			archives, err := filepath.Glob(filepath.Join(dir, "*.tar.gz"))
			require.NoError(t, err)
			require.Len(t, archives, 1)
			r := &RestoreRunner{Paths: paths, FS: fs, Env: env, Exec: &execRunner{}, Out: output, ErrOut: output}
			return r.Run(archives[0])
		}},
		{"reset-password", "psql", func() error {
			r, _, _ := newResetPasswordRunner(nil, nil)
			r.Paths = paths
			r.FS = fs
			r.Env = env
			r.Exec = &execRunner{}
			return r.Run("admin@example.com", "aB1!cD2@eF3#gH4$")
		}},
	}
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			require.NoError(t, os.WriteFile(log, nil, 0600))
			require.NoError(t, command.run())
			data, err := os.ReadFile(log)
			require.NoError(t, err)
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			require.Equal(t, filepath.Join(privateBin, command.client), lines[0])
			require.Len(t, lines, 2)
			_, err = os.Stat(lines[1])
			require.True(t, os.IsNotExist(err), "inline TLS material must be removed")
		})
	}
	require.NoError(t, os.Remove(filepath.Join(privateBin, "psql")))
	_, err := postgresClient(paths, fs, "psql")
	require.ErrorContains(t, err, "RPM runtime client")
}

func TestRealRootPathsAndDryRun(t *testing.T) {
	paths := t.TempDir()
	envPath := filepath.Join(paths, "saved.env")
	require.NoError(t, os.WriteFile(filepath.Join(paths, "runtime-manifest.json"), []byte(`{}`), 0644))
	content := []byte("JWT_SECRET=jwt\nDATABASE_PASSWORD=saved\nDATABASE_HOST=localhost\nDATABASE_PORT=6432\nHEIMDALL_DATABASE_MODE=external\nHEIMDALL_PROXY_MODE=external\n")
	require.NoError(t, os.WriteFile(envPath, content, 0640))
	out, _, err := executeCommand(t, "--app-dir", paths, "--libexec-dir", filepath.Join(paths, "missing"), "--env-file", envPath, "setup", "--dry-run")
	require.NoError(t, err)
	require.Contains(t, out, "localhost:6432")
	require.Contains(t, out, "Database mode: external")
	after, err := os.ReadFile(envPath)
	require.NoError(t, err)
	require.Equal(t, content, after)
	files, err := os.ReadDir(paths)
	require.NoError(t, err)
	require.Len(t, files, 2)
	// Production status/validate must resolve the private client from these paths.
	for _, cmd := range []string{"status", "validate"} {
		_, _, err := executeCommand(t, "--app-dir", paths, "--libexec-dir", filepath.Join(paths, "missing"), "--env-file", envPath, cmd)
		require.Error(t, err)
		require.ErrorContains(t, err, filepath.Join(paths, "missing", "runtime", "postgresql", "bin", "psql"))
	}
}
