package cmd

import (
	"fmt"
	"io"
	"os"
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
backend.env configuration file. Private Caddy configuration and certificate/CA
state are included when present. These are packaged into a private (0600), timestamped
tar.gz archive named heimdall-backup-YYYYMMDD-HHMMSS.tar.gz.

The database backup requires DATABASE_PASSWORD to be set in backend.env.
RPM installations require a successful database dump and PostgreSQL 13–18.
A newer server requires an RPM with compatible clients. Standalone installations
without a password retain configuration-only backups. Requires root privileges.`,
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

	rpm, err := r.Paths.hasRuntime(r.FS)
	if err != nil {
		return err
	}
	if rpm && env["DATABASE_PASSWORD"] == "" {
		return fmt.Errorf("RPM backup requires DATABASE_PASSWORD and a successful database dump; run setup before backing up")
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

	if err := safeManagedPath(r.FS, filepath.Join(outputDir, ".heimdall-backup-check")); err != nil {
		return err
	}
	envPath := r.Env.GetEnvFilePath()
	if err := requireRegular(r.FS, envPath); err != nil {
		return fmt.Errorf("failed to back up config: %w", err)
	}
	trees := map[string]string{}
	if rpm {
		for name, source := range recoveryTrees(r.Paths) {
			if info, err := r.FS.Lstat(source); os.IsNotExist(err) {
				continue
			} else if err != nil {
				return err
			} else if !info.IsDir() {
				return fmt.Errorf("expected private Caddy directory: %s", source)
			}
			if err := walkRecoveryTree(r.FS, source, func(string, os.FileInfo) error { return nil }); err != nil {
				return err
			}
			trees[name] = source
		}
		if err := checkPostgresServer(r.Exec, r.Paths, r.FS, dbCfg); err != nil {
			return fmt.Errorf("cannot back up database: %w; newer servers require a heimdall-server RPM with compatible PostgreSQL clients", err)
		}
	}
	ts := time.Now().Format("20060102-150405")
	backupName := "heimdall-backup-" + ts
	staging := filepath.Join(outputDir, "."+backupName)
	backupDir := filepath.Join(staging, backupName)

	if err := safeManagedPath(r.FS, filepath.Join(staging, ".heimdall-check")); err != nil {
		return err
	}
	if _, err := r.FS.Lstat(staging); err == nil {
		return fmt.Errorf("backup path already exists: %s", backupDir)
	} else if !os.IsNotExist(err) {
		return err
	}
	archive := filepath.Join(outputDir, backupName+".tar.gz")
	if err := safeManagedPath(r.FS, archive); err != nil {
		return err
	}
	if _, err := r.FS.Lstat(archive); err == nil {
		return fmt.Errorf("backup archive already exists: %s", archive)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := r.FS.MkdirAll(outputDir, 0700); err != nil {
		return err
	}
	// Exclusive creation avoids trusting a predictable directory in /tmp.
	if err := runChecked(r.Exec, "mkdir", "-m", "0700", staging); err != nil {
		return err
	}
	defer r.FS.RemoveAll(staging)
	if err := r.FS.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Copy backend.env
	if err := r.FS.CopyFile(envPath, filepath.Join(backupDir, "backend.env")); err != nil {
		fmt.Fprintf(r.ErrOut, "Config:   copy failed: %v\n", err)
		return fmt.Errorf("failed to back up config: %w", err)
	}
	if err := runChecked(r.Exec, "chmod", "0600", filepath.Join(backupDir, "backend.env")); err != nil {
		return err
	}
	for name, source := range trees {
		if err := walkRecoveryTree(r.FS, source, func(path string, info os.FileInfo) error {
			rel, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			dest := filepath.Join(backupDir, name, rel)
			if info.IsDir() {
				return r.FS.MkdirAll(dest, 0700)
			}
			if err := r.FS.CopyFile(path, dest); err != nil {
				return err
			}
			mode := os.FileMode(0600)
			if name == "caddy-config" {
				mode = info.Mode().Perm() & 0640
			}
			return runChecked(r.Exec, "chmod", fmt.Sprintf("%04o", mode), dest)
		}); err != nil {
			return fmt.Errorf("backing up %s: %w", name, err)
		}
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

	// Publish only a completed private archive, using an atomic same-filesystem rename.
	temporaryArchive := filepath.Join(staging, "archive.tar.gz")
	if err := r.FS.WriteFile(temporaryArchive, nil, 0600); err != nil {
		return err
	}
	if err := runChecked(r.Exec, "chmod", "0600", temporaryArchive); err != nil {
		return err
	}
	_, exitCode, err := r.Exec.RunWithEnv(map[string]string{"COPYFILE_DISABLE": "1"}, "tar", "czf", temporaryArchive, "-C", staging, backupName)
	if err != nil || exitCode != 0 {
		fmt.Fprintln(r.ErrOut, "Archive creation failed")
		return fmt.Errorf("failed to create archive")
	}

	if err := r.FS.Rename(temporaryArchive, archive); err != nil {
		return fmt.Errorf("publishing backup archive: %w", err)
	}
	fmt.Fprintln(r.Out)
	fmt.Fprintf(r.Out, "Backup saved to: %s\n", archive)
	return nil
}

// Only these Heimdall-owned trees supplement the logical SQL backup.
func recoveryTrees(paths Paths) map[string]string {
	config := paths.ConfigDir
	if config == "" {
		config = ConfigDir
	}
	return map[string]string{"caddy-config": filepath.Join(config, "caddy"), "caddy-state": "/var/lib/heimdall-caddy"}
}

// Validate every object, including all directory ancestors, without following links.
func walkRecoveryTree(fs FileSystem, root string, visit func(string, os.FileInfo) error) error {
	info, err := fs.Lstat(root)
	if err != nil {
		return err
	}
	check := root
	if info.IsDir() {
		check = filepath.Join(root, ".heimdall-recovery-check")
	}
	if err := safeManagedPath(fs, check); err != nil {
		return err
	}
	if err := visit(root, info); err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	entries, err := fs.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := walkRecoveryTree(fs, filepath.Join(root, entry.Name()), visit); err != nil {
			return err
		}
	}
	return nil
}
