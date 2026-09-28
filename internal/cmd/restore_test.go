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

func TestRestore_RestoresConfigAndDB(t *testing.T) {
	fs := NewFakeFileSystem()
	// Simulate the archive file exists
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake-archive")
	// After tar extraction, simulate the extracted files
	// The restore reads env AFTER copying, so we set it in FakeEnvManager
	fs.Files["/tmp/heimdall-restore--fake/backend.env"] = []byte("PORT=3000\nDATABASE_PASSWORD=secret\n")
	fs.Files["/tmp/heimdall-restore--fake/database.sql"] = []byte("-- SQL dump")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar xzf":             {Stdout: "", ExitCode: 0},
		"chown root:heimdall": {Stdout: "", ExitCode: 0},
		"psql -h":             {Stdout: "", ExitCode: 0},
	}}

	out := new(bytes.Buffer)
	r := &RestoreRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env: map[string]string{
				"DATABASE_PASSWORD": "secret",
				"DATABASE_HOST":     "localhost",
				"DATABASE_PORT":     "5432",
				"DATABASE_USERNAME": "postgres",
				"DATABASE_NAME":     "heimdall-server-production",
			},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    out,
		ErrOut: new(bytes.Buffer),
	}

	err := r.Run("/tmp/backup.tar.gz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Config:   restored") {
		t.Errorf("expected config restored message, got: %s", output)
	}
	if !strings.Contains(output, "Restart the service") {
		t.Errorf("expected restart reminder, got: %s", output)
	}

	// Verify chown was called with correct ownership for the env file
	foundChown := false
	for _, call := range exec.Calls {
		if call.Name == "chown" {
			foundChown = true
			args := strings.Join(call.Args, " ")
			if !strings.Contains(args, "root:heimdall") {
				t.Errorf("expected chown root:heimdall, got args: %s", args)
			}
			if !strings.Contains(args, "/etc/heimdall-server/backend.env") {
				t.Errorf("expected chown target to be env file, got args: %s", args)
			}
		}
	}
	if !foundChown {
		t.Error("chown should be called to set ownership on restored env file")
	}
}

func TestRestore_CallsPsqlWithCorrectArgs(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
	fs.Files["/tmp/heimdall-restore--fake/backend.env"] = []byte("x=y\n")
	fs.Files["/tmp/heimdall-restore--fake/database.sql"] = []byte("SQL")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar xzf":             {Stdout: "", ExitCode: 0},
		"chown root:heimdall": {Stdout: "", ExitCode: 0},
		"psql -h":             {Stdout: "", ExitCode: 0},
	}}

	r := &RestoreRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env: map[string]string{
				"DATABASE_PASSWORD": "pass123",
				"DATABASE_HOST":     "db.host",
				"DATABASE_PORT":     "5433",
				"DATABASE_USERNAME": "admin",
				"DATABASE_NAME":     "testdb",
			},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: new(bytes.Buffer),
	}

	require.NoError(t, r.Run("/tmp/backup.tar.gz"))

	found := false
	for _, call := range exec.Calls {
		if call.Name == "psql" {
			found = true
			assert.Equal(t, []string{
				"-h", "db.host", "-p", "5433", "-U", "admin", "-d", "testdb",
				"-X", "-v", "ON_ERROR_STOP=1", "-f", "/tmp/heimdall-restore--fake/database.sql",
			}, call.Args)
			if call.Env["PGPASSWORD"] != "pass123" {
				t.Errorf("expected PGPASSWORD=pass123, got: %s", call.Env["PGPASSWORD"])
			}
			args := strings.Join(call.Args, " ")
			if !strings.Contains(args, "-h db.host") {
				t.Errorf("expected -h db.host: %s", args)
			}
			if !strings.Contains(args, "-d testdb") {
				t.Errorf("expected -d testdb: %s", args)
			}
			break
		}
	}
	if !found {
		t.Error("psql was not called")
	}
}

func TestRestore_MissingArchive(t *testing.T) {
	fs := NewFakeFileSystem()
	r := &RestoreRunner{
		Exec:   &FakeExecRunner{},
		Env:    &FakeEnvManager{},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: new(bytes.Buffer),
	}

	err := r.Run("/nonexistent/backup.tar.gz")
	if err == nil {
		t.Fatal("expected error for missing archive")
	}
	if !strings.Contains(err.Error(), "file not found") {
		t.Errorf("expected file not found error, got: %v", err)
	}
}

func TestRestore_CorruptArchive(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/bad.tar.gz"] = []byte("corrupt")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar xzf": {Stdout: "", ExitCode: 1},
	}}

	r := &RestoreRunner{
		Exec:   exec,
		Env:    &FakeEnvManager{},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: new(bytes.Buffer),
	}

	err := r.Run("/tmp/bad.tar.gz")
	if err == nil {
		t.Fatal("expected error for corrupt archive")
	}
	if !strings.Contains(err.Error(), "failed to extract") {
		t.Errorf("expected extract error, got: %v", err)
	}
}

func TestRestore_RejectsDBWithoutPassword(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
	fs.Files["/tmp/heimdall-restore--fake/backend.env"] = []byte("PORT=3000\n")
	fs.Files["/tmp/heimdall-restore--fake/database.sql"] = []byte("SQL")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar xzf":             {Stdout: "", ExitCode: 0},
		"chown root:heimdall": {Stdout: "", ExitCode: 0},
	}}

	out := new(bytes.Buffer)
	r := &RestoreRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env:  map[string]string{},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    out,
		ErrOut: new(bytes.Buffer),
	}

	assert.Error(t, r.Run("/tmp/backup.tar.gz"))
	assert.NotContains(t, out.String(), "Restart the service")
	for _, call := range exec.Calls {
		assert.NotEqual(t, "psql", call.Name)
	}

	if !strings.Contains(out.String(), "skipped (no password in restored config)") {
		t.Errorf("expected skip message, got: %s", out.String())
	}
}

func TestRestore_ConfirmationDeclined(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")

	r := &RestoreRunner{
		Exec:     &FakeExecRunner{Results: make(map[string]FakeExecResult)},
		Env:      &FakeEnvManager{Env: map[string]string{}},
		FS:       fs,
		Out:      new(bytes.Buffer),
		ErrOut:   new(bytes.Buffer),
		Prompter: &FakePrompter{Confirms: map[string]bool{"Restore will overwrite current config and database. Continue?": false}, IsTTY: true},
	}
	err := r.Run("/tmp/backup.tar.gz")
	assert.NoError(t, err)
	assert.Contains(t, r.Out.(*bytes.Buffer).String(), "cancelled")
}

func TestRestore_SubdirectoryDetection(t *testing.T) {
	// The subdirectory detection code uses os.ReadDir (not FS interface),
	// so we need a real tmpDir. We use a RealSubdirFakeFileSystem that
	// returns a real temp dir from TempDir() but still fakes other FS ops.
	realTmpDir := t.TempDir()
	subdir := filepath.Join(realTmpDir, "backup-20260401")
	require.NoError(t, os.Mkdir(subdir, 0755))

	fs := NewFakeFileSystem()
	// Override TempDir to return the real directory
	realFS := &realTempDirFakeFS{FakeFileSystem: fs, realDir: realTmpDir}

	// Archive exists on the "fake" side
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
	// backend.env is NOT in tmpDir root, but IS in the real subdir
	// The code checks r.FS.Exists(envBackup) first — this must return false
	// Then os.ReadDir finds the real subdir.
	// After determining restoreDir, it checks r.FS.Exists on restoreDir paths.
	fs.Files[filepath.Join(subdir, "backend.env")] = []byte("PORT=3000\n")
	fs.Files[filepath.Join(subdir, "database.sql")] = []byte("-- SQL")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar xzf":             {ExitCode: 0},
		"chown root:heimdall": {ExitCode: 0},
		"psql -h":             {ExitCode: 0},
	}}

	out := new(bytes.Buffer)
	r := &RestoreRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env: map[string]string{
				"DATABASE_PASSWORD": "secret",
				"DATABASE_HOST":     "localhost",
				"DATABASE_PORT":     "5432",
				"DATABASE_USERNAME": "postgres",
				"DATABASE_NAME":     "heimdall-server-production",
			},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     realFS,
		Out:    out,
		ErrOut: new(bytes.Buffer),
	}

	err := r.Run("/tmp/backup.tar.gz")
	assert.NoError(t, err)
	assert.Contains(t, out.String(), "Config:   restored")
}

// realTempDirFakeFS wraps FakeFileSystem but returns a real temp directory.
type realTempDirFakeFS struct {
	*FakeFileSystem
	realDir string
}

func (f *realTempDirFakeFS) TempDir(prefix string) (string, error) {
	return f.realDir, nil
}

func (f *realTempDirFakeFS) RemoveAll(path string) error {
	// Don't actually remove the real tmp dir — t.TempDir() handles cleanup
	return nil
}

func TestRestore_DatabaseRestoreFailure(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
	fs.Files["/tmp/heimdall-restore--fake/backend.env"] = []byte("PORT=3000\n")
	fs.Files["/tmp/heimdall-restore--fake/database.sql"] = []byte("-- bad SQL")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar xzf":             {ExitCode: 0},
		"chown root:heimdall": {ExitCode: 0},
		"psql -h":             {Stdout: "", ExitCode: 3}, // ON_ERROR_STOP SQL error
	}}

	out := new(bytes.Buffer)
	errOut := new(bytes.Buffer)
	r := &RestoreRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env: map[string]string{
				"DATABASE_PASSWORD": "secret",
				"DATABASE_HOST":     "localhost",
				"DATABASE_PORT":     "5432",
				"DATABASE_USERNAME": "postgres",
				"DATABASE_NAME":     "heimdall-server-production",
			},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    out,
		ErrOut: errOut,
	}

	err := r.Run("/tmp/backup.tar.gz")
	assert.Error(t, err)
	assert.Contains(t, errOut.String(), "restore FAILED")
	assert.NotContains(t, out.String(), "Database: restored")
	assert.NotContains(t, out.String(), "Restart the service")
	exec.Verify(t)
}

func TestRestore_DatabaseRestoreExecError(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
	fs.Files["/tmp/heimdall-restore--fake/backend.env"] = []byte("PORT=3000\n")
	fs.Files["/tmp/heimdall-restore--fake/database.sql"] = []byte("-- SQL")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar xzf":             {ExitCode: 0},
		"chown root:heimdall": {ExitCode: 0},
		"psql -h":             {Err: fmt.Errorf("psql not found")},
	}}

	errOut := new(bytes.Buffer)
	r := &RestoreRunner{
		Exec: exec,
		Env: &FakeEnvManager{
			Env: map[string]string{
				"DATABASE_PASSWORD": "secret",
				"DATABASE_HOST":     "localhost",
				"DATABASE_PORT":     "5432",
				"DATABASE_USERNAME": "postgres",
				"DATABASE_NAME":     "heimdall-server-production",
			},
			Path: "/etc/heimdall-server/backend.env",
		},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: errOut,
	}

	err := r.Run("/tmp/backup.tar.gz")
	assert.Error(t, err)
	assert.Contains(t, errOut.String(), "restore FAILED")
	assert.NotContains(t, r.Out.(*bytes.Buffer).String(), "Restart the service")
	exec.Verify(t)
}

func TestRestore_RootCheckFails(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
	r := &RestoreRunner{
		Exec:      &FakeExecRunner{Results: make(map[string]FakeExecResult)},
		Env:       &FakeEnvManager{Env: map[string]string{}},
		FS:        fs,
		Out:       new(bytes.Buffer),
		ErrOut:    new(bytes.Buffer),
		CheckRoot: func() error { return fmt.Errorf("not root") },
	}
	err := r.Run("/tmp/backup.tar.gz")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not root")
}

func TestRestore_ConfirmPromptError(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
	r := &RestoreRunner{
		Exec:   &FakeExecRunner{Results: make(map[string]FakeExecResult)},
		Env:    &FakeEnvManager{Env: map[string]string{}},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: new(bytes.Buffer),
		Prompter: &FakePrompter{
			IsTTY: true,
			Err:   fmt.Errorf("input interrupted"),
		},
	}
	err := r.Run("/tmp/backup.tar.gz")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "input interrupted")
}

func TestRestore_ConfigCopyFails(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(fmt.Sprintf("exists=%t", exists), func(t *testing.T) {
			fs := NewFakeFileSystem()
			fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
			fs.Files["/tmp/heimdall-restore--fake/database.sql"] = []byte("SQL")
			if exists {
				// The path exists, but cannot be copied as a file.
				fs.Dirs["/tmp/heimdall-restore--fake/backend.env"] = true
			}

			exec := &FakeExecRunner{Results: map[string]FakeExecResult{
				"tar xzf": {ExitCode: 0},
			}}

			out := new(bytes.Buffer)
			r := &RestoreRunner{
				Exec:   exec,
				Env:    &FakeEnvManager{Env: map[string]string{"DATABASE_PASSWORD": "secret"}, Path: "/etc/heimdall-server/backend.env"},
				FS:     fs,
				Out:    out,
				ErrOut: new(bytes.Buffer),
			}

			err := r.Run("/tmp/backup.tar.gz")
			assert.ErrorIs(t, err, os.ErrNotExist)
			assert.NotContains(t, out.String(), "Config:   restored")
			assert.NotContains(t, out.String(), "Restart the service")
			assert.Contains(t, r.ErrOut.(*bytes.Buffer).String(), "Config:   restore failed:")
			for _, call := range exec.Calls {
				assert.NotEqual(t, "psql", call.Name, "copy failure must stop database restore")
			}
		})
	}
}

func TestRestore_ReadEnvFailsAfterRestore(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
	fs.Files["/tmp/heimdall-restore--fake/backend.env"] = []byte("PORT=3000\n")
	fs.Files["/tmp/heimdall-restore--fake/database.sql"] = []byte("-- SQL")

	exec := &FakeExecRunner{Results: map[string]FakeExecResult{
		"tar xzf":             {ExitCode: 0},
		"chown root:heimdall": {ExitCode: 0},
	}}

	errOut := new(bytes.Buffer)
	// CopyFile writes only to the fake filesystem; the real env read fails.
	r := &RestoreRunner{
		Exec:   exec,
		Env:    &FileEnvManager{Path: filepath.Join(t.TempDir(), "backend.env")},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: errOut,
	}

	err := r.Run("/tmp/backup.tar.gz")
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Contains(t, errOut.String(), "Database: could not read restored config:")
	assert.NotContains(t, r.Out.(*bytes.Buffer).String(), "Restart the service")
	for _, call := range exec.Calls {
		assert.NotEqual(t, "psql", call.Name)
	}
}

func TestRestore_NoPrompterSkipsConfirmation(t *testing.T) {
	fs := NewFakeFileSystem()
	fs.Files["/tmp/backup.tar.gz"] = []byte("fake")
	fs.Files["/tmp/heimdall-restore--fake/backend.env"] = []byte("PORT=3000\n")

	r := &RestoreRunner{
		Exec: &FakeExecRunner{Results: map[string]FakeExecResult{
			"tar xzf":             {ExitCode: 0},
			"chown root:heimdall": {ExitCode: 0},
		}},
		Env:    &FakeEnvManager{Env: map[string]string{}, Path: "/etc/heimdall-server/backend.env"},
		FS:     fs,
		Out:    new(bytes.Buffer),
		ErrOut: new(bytes.Buffer),
		// No Prompter — should skip confirmation and proceed
	}
	err := r.Run("/tmp/backup.tar.gz")
	assert.NoError(t, err)
	assert.Contains(t, r.Out.(*bytes.Buffer).String(), "Config:   restored")
}
