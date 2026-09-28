package cmd

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
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

			assert.ErrorIs(t, r.Run(t.TempDir()), os.ErrNotExist)
			assert.Empty(t, exec.Calls, "copy failure must stop the dump and archive")
			assert.Contains(t, r.ErrOut.(*bytes.Buffer).String(), "Config:   copy failed:")
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
