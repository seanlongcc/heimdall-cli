package cmd

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// BackupRunner implements the backup command.
type BackupRunner struct {
	Paths     Paths
	Exec      ExecRunner
	Env       EnvManager
	FS        FileSystem
	Out       io.Writer
	ErrOut    io.Writer
	CheckRoot func() error
}

// NewBackupCmd creates the "backup" command.
func NewBackupCmd(runner *BackupRunner) *cobra.Command {
	production := runner == nil
	if runner == nil {
		runner = &BackupRunner{
			Exec:      &execRunner{},
			Env:       NewFileEnvManager(),
			FS:        &osFileSystem{},
			CheckRoot: requireRoot,
		}
	}
	var outputDir string

	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Backup database and configuration to a timestamped archive",
		Long: `Create a backup of the Heimdall Server database and configuration. The
backup includes a pg_dump of the PostgreSQL database and a copy of the
backend.env configuration file. These are packaged into a timestamped
tar.gz archive named heimdall-backup-YYYYMMDD-HHMMSS.tar.gz.

The database backup requires DATABASE_PASSWORD to be set in backend.env.
If no password is configured, the database dump is skipped and only the
configuration file is archived. Requires root privileges.`,
		Example: `  # Create a backup in the current directory
  sudo heimdall-cli backup

  # Create a backup in a specific directory
  sudo heimdall-cli backup --output /var/backups/heimdall

  # Create a backup before upgrading
  sudo heimdall-cli backup -o /tmp && sudo dnf upgrade heimdall-server`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if production {
				runner.Paths = commandPaths(cmd)
				runner.Env = &FileEnvManager{Path: runner.Paths.EnvFile}
			}
			initIO(&runner.Out, &runner.ErrOut, cmd)
			if production && !cmd.Flags().Changed("output") {
				outputDir = filepath.Join(runner.Paths.DataDir, "backups")
			}
			return runner.Run(outputDir)
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", DataDir+"/backups", "Output directory for backup archive")
	return cmd
}

// Run performs the backup.
func (r *BackupRunner) Run(outputDir string) error {
	if r.CheckRoot != nil {
		if err := r.CheckRoot(); err != nil {
			return err
		}
	}
	env, err := r.Env.ReadEnv()
	if err != nil {
		return fmt.Errorf("failed to read env: %w", err)
	}

	dbCfg, err := resolveDBConfig(env)
	if err != nil {
		return err
	}
	binary, err := postgresClient(r.Paths, r.FS, "pg_dump")
	if err != nil {
		return err
	}

	// Validate output directory to prevent path traversal
	if !filepath.IsAbs(outputDir) {
		return fmt.Errorf("output directory must be absolute path, got: %s", outputDir)
	}
	if strings.Contains(outputDir, "..") {
		return fmt.Errorf("output directory must not contain path traversal (..): %s", outputDir)
	}

	ts := time.Now().Format("20060102-150405")
	backupName := "heimdall-backup-" + ts
	backupDir := filepath.Join(outputDir, backupName)

	if err := r.FS.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Copy backend.env
	envPath := r.Env.GetEnvFilePath()
	if err := r.FS.CopyFile(envPath, filepath.Join(backupDir, "backend.env")); err != nil {
		fmt.Fprintf(r.ErrOut, "Config:   copy failed: %v\n", err)
		return fmt.Errorf("failed to back up config: %w", err)
	}
	fmt.Fprintln(r.Out, "Config:   backed up")

	// Database backup
	if dbCfg.Password != "" {
		dumpFile := filepath.Join(backupDir, "database.sql")
		pgEnv := dbCfg.PgEnv()
		_, exitCode, err := r.Exec.RunWithEnv(pgEnv, binary,
			"-h", dbCfg.Host, "-p", dbCfg.PortStr(), "-U", dbCfg.User, dbCfg.DBName, "-f", dumpFile)
		if err != nil || exitCode != 0 {
			fmt.Fprintln(r.ErrOut, "Database: backup FAILED")
			if err != nil {
				return fmt.Errorf("failed to back up database: %w", err)
			}
			return fmt.Errorf("failed to back up database: pg_dump exited with status %d", exitCode)
		} else {
			fmt.Fprintln(r.Out, "Database: backed up")
		}
	} else {
		fmt.Fprintln(r.Out, "Database: skipped (no password configured)")
	}

	// Create tar.gz archive
	archive := backupDir + ".tar.gz"
	_, exitCode, err := r.Exec.Run("tar", "czf", archive, "-C", outputDir, backupName)
	if err != nil || exitCode != 0 {
		fmt.Fprintf(r.ErrOut, "Archive creation failed. Files in: %s\n", backupDir)
		return fmt.Errorf("failed to create archive")
	}

	// Clean up temp directory
	_ = r.FS.RemoveAll(backupDir)

	fmt.Fprintln(r.Out)
	fmt.Fprintf(r.Out, "Backup saved to: %s\n", archive)
	return nil
}
