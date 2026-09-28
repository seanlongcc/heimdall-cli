package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// RestoreRunner implements the restore command.
type RestoreRunner struct {
	Exec      ExecRunner
	Env       EnvManager
	FS        FileSystem
	Out       io.Writer
	ErrOut    io.Writer
	CheckRoot func() error
	Prompter  Prompter
}

// NewRestoreCmd creates the "restore" command.
func NewRestoreCmd(runner *RestoreRunner) *cobra.Command {
	if runner == nil {
		runner = &RestoreRunner{
			Exec:      &execRunner{},
			Env:       NewFileEnvManager(),
			FS:        &osFileSystem{},
			CheckRoot: requireRoot,
		}
	}
	return &cobra.Command{
		Use:   "restore <archive.tar.gz>",
		Short: "Restore database and configuration from a backup archive",
		Long: `Restore the Heimdall Server database and configuration from a backup
archive created by 'heimdall-cli backup'. The archive is extracted to
a temporary directory, backend.env is restored with proper ownership
(root:heimdall, mode 0640), and the database SQL dump is replayed
using psql.

The database credentials are read from the restored backend.env, so
the restore is self-contained. After restoring, you must restart the
service manually for changes to take effect. Requires root privileges.`,
		Example: `  # Restore from a backup archive
  sudo heimdall-cli restore /var/backups/heimdall/heimdall-backup-20260401-120000.tar.gz

  # Restore and immediately restart the service
  sudo heimdall-cli restore /tmp/heimdall-backup-20260401-120000.tar.gz && \
    sudo systemctl restart heimdall-server`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			initIO(&runner.Out, &runner.ErrOut, cmd)
			return runner.Run(args[0])
		},
	}
}

// Run performs the restore from a .tar.gz archive.
func (r *RestoreRunner) Run(archive string) error {
	if r.CheckRoot != nil {
		if err := r.CheckRoot(); err != nil {
			return err
		}
	}
	if !r.FS.Exists(archive) {
		return fmt.Errorf("file not found: %s", archive)
	}

	// Confirmation prompt for destructive operation
	if r.Prompter != nil && r.Prompter.CanPrompt() {
		ok, err := r.Prompter.Confirm("Restore will overwrite current config and database. Continue?", false)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(r.Out, "Restore cancelled.")
			return nil
		}
	}

	tmpDir, err := r.FS.TempDir("heimdall-restore-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer r.FS.RemoveAll(tmpDir)

	// Extract archive with path traversal protection
	_, exitCode, err := r.Exec.Run("tar", "xzf", archive, "-C", tmpDir,
		"--no-same-owner", "--no-same-permissions")
	if err != nil || exitCode != 0 {
		return fmt.Errorf("failed to extract archive")
	}

	// Determine restore directory: check if backend.env is directly in tmpDir,
	// otherwise look for a single subdirectory (standard tar extraction pattern).
	restoreDir := tmpDir
	envBackup := filepath.Join(tmpDir, "backend.env")
	if !r.FS.Exists(envBackup) {
		// Try to find a subdirectory created by tar extraction
		entries, err := os.ReadDir(tmpDir)
		if err == nil && len(entries) == 1 && entries[0].IsDir() {
			restoreDir = filepath.Join(tmpDir, entries[0].Name())
		}
	}

	// Restore config
	envBackup = filepath.Join(restoreDir, "backend.env")
	envDest := r.Env.GetEnvFilePath()
	if err := r.FS.CopyFile(envBackup, envDest); err != nil {
		fmt.Fprintf(r.ErrOut, "Config:   restore failed: %v\n", err)
		return fmt.Errorf("failed to restore config: %w", err)
	}
	// Set permissions and ownership
	_ = os.Chmod(envDest, 0640)
	r.Exec.Run("chown", "root:heimdall", envDest)
	fmt.Fprintln(r.Out, "Config:   restored")

	// Restore database
	sqlBackup := filepath.Join(restoreDir, "database.sql")
	if r.FS.Exists(sqlBackup) {
		// Re-read env from restored config
		env, err := r.Env.ReadEnv()
		if err != nil {
			fmt.Fprintf(r.ErrOut, "Database: could not read restored config: %v\n", err)
			return fmt.Errorf("failed to read restored config: %w", err)
		} else {
			dbCfg := ExtractDBConfig(env)

			if dbCfg.Password != "" {
				pgEnv := dbCfg.PgEnv()
				_, exitCode, err := r.Exec.RunWithEnv(pgEnv, "psql",
					"-h", dbCfg.Host, "-p", dbCfg.PortStr(), "-U", dbCfg.User, "-d", dbCfg.DBName,
					"-X", "-v", "ON_ERROR_STOP=1", "-f", sqlBackup)
				if err != nil || exitCode != 0 {
					fmt.Fprintln(r.ErrOut, "Database: restore FAILED")
					if err != nil {
						return fmt.Errorf("failed to restore database: %w", err)
					}
					return fmt.Errorf("failed to restore database: psql exited with status %d", exitCode)
				} else {
					fmt.Fprintln(r.Out, "Database: restored")
				}
			} else {
				fmt.Fprintln(r.Out, "Database: skipped (no password in restored config)")
				return fmt.Errorf("cannot restore database.sql without a password in restored config")
			}
		}
	}

	fmt.Fprintln(r.Out)
	fmt.Fprintf(r.Out, "Restart the service: sudo systemctl restart %s\n", ServiceName)
	return nil
}
