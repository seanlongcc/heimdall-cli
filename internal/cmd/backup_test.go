package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackup_CreatesArchive(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/etc/heimdall-server/backend.env"] = []byte("PORT=3000\nDATABASE_PASSWORD=secret\n")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"pg_dump -h": {Stdout: "", ExitCode: 0},
		"tar czf":    {Stdout: "", ExitCode: 0},
	}}

	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	r := &BackupRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env:  map[string]string{"DATABASE_PASSWORD": "secret", "DATABASE_HOST": "localhost"},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    out,
		ErrOut: errOut,
	}

	err := r.Run(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Config:   backed up") {
		t.Errorf("expected config backed up message, got: %s", output)
	}
	if !strings.Contains(output, "Backup saved to:") {
		t.Errorf("expected backup saved message, got: %s", output)
	}

	// Verify pg_dump was called (database backup attempted)
	foundPgDump := false
	for _, call := range exec.Calls {
		if call.Name == "pg_dump" {
			foundPgDump = true
			assert.Equal(t, "secret", call.Env["PGPASSWORD"], "PGPASSWORD should be passed to pg_dump")
		}
	}
	assert.True(t, foundPgDump, "pg_dump should be called for database backup")
}

func TestBackup_CallsPgDumpWithCorrectArgs(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/etc/heimdall-server/backend.env"] = []byte("PORT=3000\n")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"pg_dump -h": {Stdout: "", ExitCode: 0},
		"tar czf":    {Stdout: "", ExitCode: 0},
	}}

	r := &BackupRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env: map[string]string{
				"DATABASE_PASSWORD": "mypass",
				"DATABASE_HOST":     "db.local",
				"DATABASE_PORT":     "5433",
				"DATABASE_USERNAME": "heimdall",
				"DATABASE_NAME":     "mydb",
			},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: new(bytes.Buffer),
	}

	_ = r.Run(t.TempDir())

	// Find the pg_dump call
	found := false
	for _, call := range exec.Calls {
		if call.Name == "pg_dump" {
			found = true
			if call.Env["PGPASSWORD"] != "mypass" {
				t.Errorf("expected PGPASSWORD=mypass, got: %s", call.Env["PGPASSWORD"])
			}
			args := strings.Join(call.Args, " ")
			if !strings.Contains(args, "-h db.local") {
				t.Errorf("expected -h db.local in args: %s", args)
			}
			if !strings.Contains(args, "-p 5433") {
				t.Errorf("expected -p 5433 in args: %s", args)
			}
			if !strings.Contains(args, "-U heimdall") {
				t.Errorf("expected -U heimdall in args: %s", args)
			}
			if !strings.Contains(args, "mydb") {
				t.Errorf("expected mydb in args: %s", args)
			}
			break
		}
	}
	if !found {
		t.Error("pg_dump was not called")
	}
}

func TestBackup_HandlesPgDumpFailure(t *testing.T) {
	for _, failure := range []struct {
		name   string
		result FakeExecResult
	}{
		{"exit status", FakeExecResult{ExitCode: 1}},
		{"exec error", FakeExecResult{Err: fmt.Errorf("pg_dump not found")}},
	} {
		t.Run(failure.name, func(t *testing.T) {
			fs := NewFakeFileSystem()
			fs.Files["/etc/heimdall-server/backend.env"] = []byte("PORT=3000\n")

			exec := &FakeExecRunner{Results: map[string]FakeExecResult{
				"pg_dump -h": failure.result,
			}}

			errOut := new(bytes.Buffer)
			r := &BackupRunner{
				Exec: exec,
				Env: &FakeEnvManager{
					Env:  map[string]string{"DATABASE_PASSWORD": "secret"},
					Path: "/etc/heimdall-server/backend.env",
				},
				FS:     fs,
				Out:    new(bytes.Buffer),
				ErrOut: errOut,
			}

			assert.Error(t, r.Run(t.TempDir()))
			assert.NotContains(t, r.Out.(*bytes.Buffer).String(), "Backup saved to:")
			for _, call := range exec.Calls {
				assert.NotEqual(t, "tar", call.Name, "a failed database dump must not be archived")
			}
			exec.Verify(t)

			if !strings.Contains(errOut.String(), "backup FAILED") {
				t.Errorf("expected FAILED message on stderr, got: %s", errOut.String())
			}
		})
	}
}

func TestBackup_ConfigCopyFailure(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(fmt.Sprintf("exists=%t", exists), func(t *testing.T) {
			fs := NewFakeFileSystem()
			if exists {
				// The path exists, but cannot be copied as a file.
				fs.Dirs["/etc/heimdall-server/backend.env"] = true
			}
			exec := &FakeExecRunner{}
			r := &BackupRunner{
				Exec:   exec,
				Env:    &FakeEnvManager{Env: map[string]string{"DATABASE_PASSWORD": "secret"}},
				FS:     fs,
				Out:    new(bytes.Buffer),
				ErrOut: new(bytes.Buffer),
			}

			assert.Error(t, r.Run(t.TempDir()))
			assert.Empty(t, exec.Calls, "copy failure must stop the dump and archive")
			assert.NotContains(t, r.Out.(*bytes.Buffer).String(), "Backup saved to:")
		})
	}
}

func TestBackup_ConfigReadFailure(t *testing.T) {
	exec := &FakeExecRunner{}
	r := &BackupRunner{
		Exec:   exec,
		Env:    &FileEnvManager{Path: t.TempDir()},
		FS:     NewFakeFileSystem(),
		Out:    new(bytes.Buffer),
		ErrOut: new(bytes.Buffer),
	}
	assert.Error(t, r.Run(t.TempDir()))
	assert.Empty(t, exec.Calls)
}

func TestBackup_SkipsDBWithoutPassword(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/etc/heimdall-server/backend.env"] = []byte("PORT=3000\n")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar czf": {Stdout: "", ExitCode: 0},
	}}

	out := new(bytes.Buffer)
	r := &BackupRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env:  map[string]string{},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    out,
		ErrOut: new(bytes.Buffer),
	}

	assert.NoError(t, r.Run(t.TempDir()))
	assert.Contains(t, out.String(), "Backup saved to:")

	if !strings.Contains(out.String(), "skipped (no password configured)") {
		t.Errorf("expected skip message, got: %s", out.String())
	}

	// Verify pg_dump was NOT called
	for _, call := range exec.Calls {
		if call.Name == "pg_dump" {
			t.Error("pg_dump should not be called without a password")
		}
	}
}

func TestBackup_IncludesEnvInArchive(t *testing.T) {
	fs := NewFakeFileSystem()
	envContent := []byte("PORT=3000\nDATABASE_PASSWORD=secret\n")
	fs.Files["/etc/heimdall-server/backend.env"] = envContent

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"pg_dump -h": {Stdout: "", ExitCode: 0},
		"tar czf":    {Stdout: "", ExitCode: 0},
	}}

	r := &BackupRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env:  map[string]string{"DATABASE_PASSWORD": "secret"},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: new(bytes.Buffer),
	}

	tmpDir := t.TempDir()
	_ = r.Run(tmpDir)

	// The backup copies env then tars and removes the temp dir.
	// Verify tar was called (which archives the copied env file).
	foundTar := false
	for _, call := range exec.Calls {
		if call.Name == "tar" && len(call.Args) > 0 && call.Args[0] == "czf" {
			foundTar = true
			// The archive path should be in the output dir
			if !strings.HasPrefix(call.Args[1], tmpDir) {
				t.Errorf("expected archive in %s, got: %s", tmpDir, call.Args[1])
			}
		}
	}
	if !foundTar {
		t.Error("tar should have been called to create archive")
	}

	// Verify config backed up message appeared
	out := r.Out.(*bytes.Buffer).String()
	if !strings.Contains(out, "Config:   backed up") {
		t.Errorf("expected config backed up message, got: %s", out)
	}
}

func TestBackup_ArchiveCreationFailure(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/etc/heimdall-server/backend.env"] = []byte("PORT=3000\n")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar czf": {Stdout: "", ExitCode: 1, Err: fmt.Errorf("tar failed")},
	}}

	errOut := new(bytes.Buffer)
	r := &BackupRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env:  map[string]string{},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: errOut,
	}

	err := r.Run(t.TempDir())
	if err == nil {
		t.Fatal("expected error when archive creation fails")
	}
}

func TestBackup_RejectsRelativePath(t *testing.T) {
	r := &BackupRunner{
		Env:       &FakeEnvManager{Env: map[string]string{"DATABASE_PASSWORD": "pass"}},
		Exec:      &FakeExecRunner{Results: make(map[string]FakeExecResult)},
		FS:        NewFakeFileSystem(),
		Out:       new(bytes.Buffer),
		ErrOut:    new(bytes.Buffer),
		CheckRoot: func() error { return nil },
	}
	err := r.Run("../../../tmp/evil")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestBackup_RejectsPathTraversal(t *testing.T) {
	r := &BackupRunner{
		Env:       &FakeEnvManager{Env: map[string]string{"DATABASE_PASSWORD": "pass"}},
		Exec:      &FakeExecRunner{Results: make(map[string]FakeExecResult)},
		FS:        NewFakeFileSystem(),
		Out:       new(bytes.Buffer),
		ErrOut:    new(bytes.Buffer),
		CheckRoot: func() error { return nil },
	}
	err := r.Run("/var/lib/../../../etc/passwd")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "traversal")
}

func TestBackupRPMRequiresDatabaseAndCompatibleServer(t *testing.T) {
	for _, tc := range []struct {
		name, password, version string
		ok                      bool
	}{
		{"missing password", "", "180006", false}, {"old", "secret", "120015", false}, {"newer", "secret", "190000", false}, {"malformed", "secret", "", false}, {"floor", "secret", "130022", true}, {"ceiling", "secret", "180006", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, fs, e := recoveryFixture(t, true)
			e.version = tc.version
			err := os.WriteFile(p.EnvFile, []byte("DATABASE_PASSWORD="+tc.password+"\n"), 0640)
			require.NoError(t, err)
			out := new(bytes.Buffer)
			r := &BackupRunner{Paths: p, FS: fs, Exec: e, Env: &FileEnvManager{Path: p.EnvFile}, Out: out, ErrOut: out}
			err = r.Run(filepath.Dir(p.ConfigDir))
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				archives, _ := filepath.Glob(filepath.Join(filepath.Dir(p.ConfigDir), "*.tar.gz"))
				require.Empty(t, archives)
				require.NotContains(t, out.String(), "Backup saved")
			}
		})
	}
}

func TestBackupRejectsUnsafeSourcesAndOutput(t *testing.T) {
	for _, kind := range []string{"config symlink", "Caddy symlink", "Caddy hardlink", "output symlink", "output file"} {
		t.Run(kind, func(t *testing.T) {
			p, fs, e := recoveryFixture(t, true)
			outside := filepath.Join(filepath.Dir(p.ConfigDir), "outside")
			require.NoError(t, os.WriteFile(outside, []byte("untouched"), 0600))
			output := filepath.Join(filepath.Dir(p.ConfigDir), "backups")
			switch kind {
			case "config symlink":
				require.NoError(t, os.Remove(p.EnvFile))
				require.NoError(t, os.Symlink(outside, p.EnvFile))
			case "Caddy symlink":
				require.NoError(t, os.Symlink(filepath.Dir(p.ConfigDir), p.ConfigDir+"/caddy"))
			case "Caddy hardlink":
				require.NoError(t, os.Mkdir(p.ConfigDir+"/caddy", 0700))
				require.NoError(t, os.Link(outside, p.ConfigDir+"/caddy/Caddyfile"))
			case "output symlink":
				require.NoError(t, os.Symlink(filepath.Dir(p.ConfigDir), output))
			case "output file":
				require.NoError(t, os.WriteFile(output, []byte("untouched"), 0600))
			}
			r := &BackupRunner{Paths: p, FS: fs, Exec: e, Env: &FileEnvManager{Path: p.EnvFile}, Out: new(bytes.Buffer), ErrOut: new(bytes.Buffer)}
			require.Error(t, r.Run(output))
			require.Empty(t, e.calls)
			data, err := os.ReadFile(outside)
			require.NoError(t, err)
			require.Equal(t, "untouched", string(data))
		})
	}
}

func TestBackupCommandFailuresDoNotClaimSuccess(t *testing.T) {
	for _, fail := range []string{"SHOW server_version_num", "pg_dump", "tar czf", "chmod 0600", "mkdir -m"} {
		t.Run(fail, func(t *testing.T) {
			p, fs, e := recoveryFixture(t, true)
			e.fail = fail
			out := new(bytes.Buffer)
			r := &BackupRunner{Paths: p, FS: fs, Exec: e, Env: &FileEnvManager{Path: p.EnvFile}, Out: out, ErrOut: out}
			require.Error(t, r.Run(filepath.Dir(p.ConfigDir)))
			require.NotContains(t, out.String(), "Backup saved to:")
		})
	}
}

func TestBackupRPMAcceptsResolvedURLCredentials(t *testing.T) {
	p, fs, e := recoveryFixture(t, true)
	require.NoError(t, os.WriteFile(p.EnvFile, []byte("DATABASE_URL=postgres://backup:secret@db.example.test:5432/heimdall\nHEIMDALL_DATABASE_MODE=external\n"), 0600))
	r := &BackupRunner{Paths: p, FS: fs, Exec: e, Env: &FileEnvManager{Path: p.EnvFile}, Out: new(bytes.Buffer), ErrOut: new(bytes.Buffer)}
	require.NoError(t, r.Run(filepath.Join(filepath.Dir(p.ConfigDir), "url-backups")))
	var dumped bool
	for _, call := range e.calls {
		if filepath.Base(call.Name) == "pg_dump" {
			dumped = true
			require.Equal(t, "secret", call.Env["PGPASSWORD"])
			require.Contains(t, call.Args, "db.example.test")
			require.Contains(t, call.Args, "backup")
			require.Contains(t, call.Args, "heimdall")
		}
	}
	require.True(t, dumped, "URL-only credentials must produce the required SQL dump")
}

type backupSwapAfterCheckFS struct {
	*recoveryFS
	target  string
	reads   int
	swapped bool
	swap    func() error
}

func (f *backupSwapAfterCheckFS) Lstat(path string) (os.FileInfo, error) {
	info, err := f.recoveryFS.Lstat(path)
	if err != nil {
		return info, err
	}
	if path == f.target {
		f.reads++
	}
	// The fourth leaf stat is the copy walk's guard, after the initial preflight.
	// Swap only after the last ancestor check returns its original metadata.
	if f.reads == 4 && !f.swapped && path == "/var" {
		if err := f.swap(); err != nil {
			return nil, err
		}
		f.swapped = true
	}
	return info, nil
}
func TestBackupConfinesSourceReadAfterPreflight(t *testing.T) {
	for _, kind := range []string{"leaf symlink", "ancestor symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			p, fs, e := recoveryFixture(t, true)
			require.NoError(t, os.MkdirAll(fs.state+"/data", 0700))
			target := fs.state + "/data/key"
			require.NoError(t, os.WriteFile(target, []byte("owned state"), 0600))
			outside := filepath.Join(filepath.Dir(fs.state), "outside")
			require.NoError(t, os.Mkdir(outside, 0700))
			require.NoError(t, os.WriteFile(outside+"/key", []byte("outside data must never be archived"), 0600))
			racing := &backupSwapAfterCheckFS{recoveryFS: fs, target: "/var/lib/heimdall-caddy/data/key", swap: func() error {
				leaf := target
				link := outside + "/key"
				if kind == "ancestor symlink" {
					leaf = fs.state + "/data"
					link = outside
				}
				if err := os.Rename(leaf, leaf+".prior"); err != nil {
					return err
				}
				if kind == "hardlink" {
					return os.Link(link, leaf)
				}
				return os.Symlink(link, leaf)
			}}
			out := new(bytes.Buffer)
			r := &BackupRunner{Paths: p, FS: racing, Exec: e, Env: &FileEnvManager{Path: p.EnvFile}, Out: out, ErrOut: out}
			require.Error(t, r.Run(filepath.Dir(p.ConfigDir)))
			require.True(t, racing.swapped)
			archives, err := filepath.Glob(filepath.Join(filepath.Dir(p.ConfigDir), "*.tar.gz"))
			require.NoError(t, err)
			require.Empty(t, archives)
			require.NotContains(t, out.String(), "Backup saved")
		})
	}
}
