package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// SetupRunner orchestrates the 7-step setup process using injected dependencies.
type SetupRunner struct {
	Exec     ExecRunner
	Systemd  SystemdRunner
	Env      EnvManager
	FS       FileSystem
	DB       DBConnector
	Prompter Prompter
	Terminal TerminalDetector
	Out      io.Writer
	ErrOut   io.Writer
	Paths    Paths

	// Flags
	Interactive bool
	NonInteract bool
	DBHost      string
	DBPort      int
	DBUser      string
	DBPassword  string
	DBName      string
	ExternalURL string
	TLSCert     string
	TLSKey      string
	SkipDB      bool
	SkipTLS     bool
	Reconfigure bool
	DryRun      bool
}

// NewSetupCmd creates the setup cobra command. If runner is nil, a default
// runner is used (for production); tests inject a pre-configured runner.
func NewSetupCmd(runner *SetupRunner) *cobra.Command {
	if runner == nil {
		runner = &SetupRunner{
			Exec:     &execRunner{},
			Systemd:  &systemdRunner{},
			Env:      NewFileEnvManager(),
			FS:       &osFileSystem{},
			DB:       &psqlConnector{},
			Prompter: &huhPrompter{},
			Terminal: &stdioDetector{},
			Paths:    DefaultPaths(),
		}
	}

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Run post-install setup for Heimdall Server",
		Long: `Run the full post-install setup wizard for Heimdall Server. This command
orchestrates seven steps in sequence:

  1. Configuration   Write backend.env with database credentials and secrets
  2. PostgreSQL      Bootstrap local PostgreSQL (skipped for external databases)
  3. Connection test Verify database connectivity with SELECT 1
  4. Migrations      Run heimdall-server-db-setup to create/update schema
  5. TLS proxy       Configure Caddy as a reverse proxy with HTTPS
  6. Security        Apply SELinux policies, fapolicyd trust, and firewalld rules
  7. Service start   Enable and start the heimdall-server systemd unit

Steps can be selectively skipped with --skip-db and --skip-tls. Use
--reconfigure to re-run only step 1 without restarting the full pipeline.
Cloud environments (AWS, Azure, GCP) are auto-detected for security group hints.`,
		Example: `  # Full interactive setup with local PostgreSQL
  sudo heimdall-cli setup --interactive

  # Non-interactive setup with an external database
  sudo heimdall-cli setup --non-interactive \
    --db-host db.example.com --db-port 5432 \
    --db-user heimdall --db-password secret \
    --external-url https://heimdall.example.com

  # Re-run setup skipping TLS (already handled by load balancer)
  sudo heimdall-cli setup --non-interactive --skip-tls

  # Update only the configuration file without restarting services
  sudo heimdall-cli setup --reconfigure --db-host new-db.example.com`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Validate TLS flags
			certSet := runner.TLSCert != ""
			keySet := runner.TLSKey != ""
			if !runner.SkipTLS && (certSet != keySet) {
				return fmt.Errorf("--tls-cert and --tls-key must be provided together")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			initIO(&runner.Out, &runner.ErrOut, cmd)
			return runner.Run()
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&runner.Interactive, "interactive", false, "Prompt for configuration values")
	flags.BoolVar(&runner.NonInteract, "non-interactive", false, "Accept defaults and auto-generate secrets")
	flags.StringVar(&runner.DBHost, "db-host", "localhost", "Database host")
	flags.IntVar(&runner.DBPort, "db-port", 5432, "Database port")
	flags.StringVar(&runner.DBUser, "db-user", "postgres", "Database user")
	flags.StringVar(&runner.DBPassword, "db-password", "", "Database password")
	flags.StringVar(&runner.DBName, "db-name", "heimdall-server-production", "Database name")
	flags.StringVar(&runner.ExternalURL, "external-url", "", "Public URL (e.g. https://heimdall.example.com)")
	flags.StringVar(&runner.TLSCert, "tls-cert", "", "Path to TLS certificate (PEM)")
	flags.StringVar(&runner.TLSKey, "tls-key", "", "Path to TLS private key (PEM)")
	flags.BoolVar(&runner.SkipDB, "skip-db", false, "Skip PostgreSQL bootstrap and migrations")
	flags.BoolVar(&runner.SkipTLS, "skip-tls", false, "Skip TLS reverse proxy setup")
	flags.BoolVar(&runner.Reconfigure, "reconfigure", false, "Re-run only the configuration step")
	flags.BoolVar(&runner.DryRun, "dry-run", false, "Show what setup would do without making changes")

	return cmd
}

// Run executes the 7-step setup.
func (r *SetupRunner) Run() error {
	isLocalDB := isLocalHost(r.DBHost)

	if r.DryRun {
		return r.printDryRun(isLocalDB)
	}

	// Pre-flight summary
	r.printSummary(isLocalDB)

	// Step 1: Configuration
	fmt.Fprintln(r.Out, "=== Step 1/7: Configuration ===")
	if err := r.stepConfigure(); err != nil {
		return WrapError(err, "configuration failed",
			"Check file permissions: ls -la "+r.Env.GetEnvFilePath())
	}

	if r.Reconfigure {
		fmt.Fprintln(r.Out)
		fmt.Fprintln(r.Out, "Reconfiguration complete. Restart the service to apply changes:")
		fmt.Fprintf(r.Out, "  sudo systemctl restart %s\n", ServiceName)
		return nil
	}

	// Step 2: PostgreSQL bootstrap
	fmt.Fprintln(r.Out)
	if r.SkipDB {
		fmt.Fprintln(r.Out, "=== Step 2/7: PostgreSQL bootstrap (skipped -- --skip-db) ===")
	} else if !isLocalDB {
		fmt.Fprintln(r.Out, "=== Step 2/7: PostgreSQL bootstrap (skipped -- external database) ===")
	} else {
		fmt.Fprintln(r.Out, "=== Step 2/7: PostgreSQL bootstrap ===")
		if err := r.stepPostgresBootstrap(); err != nil {
			return WrapError(err, "PostgreSQL bootstrap failed",
				"Check PostgreSQL is installed: sudo dnf install postgresql-server")
		}
	}

	// Step 3: Connection test
	fmt.Fprintln(r.Out)
	if r.SkipDB {
		fmt.Fprintln(r.Out, "=== Step 3/7: Connection test (skipped -- --skip-db) ===")
	} else {
		fmt.Fprintln(r.Out, "=== Step 3/7: Connection test ===")
		if err := r.stepConnectionTest(); err != nil {
			return WrapError(err, "database connection test failed",
				"Check PostgreSQL is running: sudo systemctl status postgresql")
		}
	}

	// Step 4: Database migrations
	fmt.Fprintln(r.Out)
	if r.SkipDB {
		fmt.Fprintln(r.Out, "=== Step 4/7: Database migrations (skipped -- --skip-db) ===")
	} else {
		fmt.Fprintln(r.Out, "=== Step 4/7: Database migrations ===")
		if err := r.stepMigrations(); err != nil {
			return WrapError(err, "database migrations failed",
				"Check DB connectivity: sudo heimdall-cli validate")
		}
	}

	// Step 5: TLS reverse proxy
	fmt.Fprintln(r.Out)
	if r.SkipTLS {
		fmt.Fprintln(r.Out, "=== Step 5/7: TLS reverse proxy (skipped -- --skip-tls) ===")
	} else {
		fmt.Fprintln(r.Out, "=== Step 5/7: TLS reverse proxy ===")
		if err := r.stepTLS(); err != nil {
			return WrapError(err, "TLS setup failed",
				"Skip TLS and configure later: sudo heimdall-cli setup --skip-tls")
		}
	}

	// Step 6: Security policies
	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, "=== Step 6/7: Security policies ===")
	r.stepSecurityPolicies()

	// Step 7: Start service
	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, "=== Step 7/7: Starting service ===")
	if err := r.stepStartService(); err != nil {
		return WrapError(err, "service start failed",
			"Check config: sudo heimdall-cli validate && sudo systemctl status "+ServiceName)
	}

	r.printCompletionBanner()
	return nil
}

func (r *SetupRunner) printSummary(isLocalDB bool) {
	fmt.Fprintln(r.Out, "Heimdall Server Setup")
	fmt.Fprintln(r.Out, "---------------------")
	fmt.Fprintf(r.Out, "  Database host: %s:%d\n", r.DBHost, r.DBPort)
	fmt.Fprintf(r.Out, "  Database name: %s\n", r.DBName)
	if r.SkipDB {
		fmt.Fprintln(r.Out, "  PostgreSQL bootstrap: skip (--skip-db)")
		fmt.Fprintln(r.Out, "  Database migrations:  skip (--skip-db)")
	} else if !isLocalDB {
		fmt.Fprintln(r.Out, "  PostgreSQL bootstrap: skip (external database)")
		fmt.Fprintln(r.Out, "  Database migrations:  run")
	} else {
		fmt.Fprintln(r.Out, "  PostgreSQL bootstrap: run")
		fmt.Fprintln(r.Out, "  Database migrations:  run")
	}
	if r.SkipTLS {
		fmt.Fprintln(r.Out, "  TLS reverse proxy:    skip (--skip-tls)")
	} else {
		fmt.Fprintln(r.Out, "  TLS reverse proxy:    run")
	}
	fmt.Fprintln(r.Out)
}

// printDryRun shows what setup would do without making any changes.
func (r *SetupRunner) printDryRun(isLocalDB bool) error {
	fmt.Fprintln(r.Out, "=== DRY RUN — no changes will be made ===")
	fmt.Fprintln(r.Out)

	fmt.Fprintln(r.Out, "=== Step 1/7: Configuration ===")
	fmt.Fprintf(r.Out, "  Would write config to %s\n", r.Env.GetEnvFilePath())
	fmt.Fprintf(r.Out, "  Database: %s@%s:%d/%s\n", r.DBUser, r.DBHost, r.DBPort, r.DBName)
	if r.DBPassword == "" {
		fmt.Fprintln(r.Out, "  DATABASE_PASSWORD: would auto-generate")
	}

	fmt.Fprintln(r.Out)
	if r.SkipDB {
		fmt.Fprintln(r.Out, "=== Step 2/7: PostgreSQL bootstrap (skipped -- --skip-db) ===")
	} else if !isLocalDB {
		fmt.Fprintln(r.Out, "=== Step 2/7: PostgreSQL bootstrap (skipped -- external database) ===")
	} else {
		fmt.Fprintln(r.Out, "=== Step 2/7: PostgreSQL bootstrap ===")
		fmt.Fprintln(r.Out, "  Would bootstrap local PostgreSQL (detect, init, configure, role, database)")
	}

	fmt.Fprintln(r.Out)
	if r.SkipDB {
		fmt.Fprintln(r.Out, "=== Step 3/7: Connection test (skipped -- --skip-db) ===")
	} else {
		fmt.Fprintln(r.Out, "=== Step 3/7: Connection test ===")
		fmt.Fprintf(r.Out, "  Would test: %s:%d/%s\n", r.DBHost, r.DBPort, r.DBName)
	}

	fmt.Fprintln(r.Out)
	if r.SkipDB {
		fmt.Fprintln(r.Out, "=== Step 4/7: Database migrations (skipped -- --skip-db) ===")
	} else {
		fmt.Fprintln(r.Out, "=== Step 4/7: Database migrations ===")
		fmt.Fprintln(r.Out, "  Would run: heimdall-server-db-setup")
	}

	fmt.Fprintln(r.Out)
	if r.SkipTLS {
		fmt.Fprintln(r.Out, "=== Step 5/7: TLS reverse proxy (skipped -- --skip-tls) ===")
	} else {
		fmt.Fprintln(r.Out, "=== Step 5/7: TLS reverse proxy ===")
		fmt.Fprintln(r.Out, "  Would configure Caddy TLS reverse proxy")
		if r.TLSCert != "" {
			fmt.Fprintf(r.Out, "  Cert: %s\n  Key: %s\n", r.TLSCert, r.TLSKey)
		}
	}

	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, "=== Step 6/7: Security policies ===")
	fmt.Fprintln(r.Out, "  Would configure: SELinux, fapolicyd, firewalld, file permissions")

	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, "=== Step 7/7: Starting service ===")
	fmt.Fprintf(r.Out, "  Would enable and start: %s\n", ServiceName)

	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, "=== End DRY RUN — run without --dry-run to apply ===")
	return nil
}

// stepConfigure writes backend.env with DB credentials and secrets.
// In --interactive mode, prompts the user for each value.
// Preserves existing values — only generates secrets if they don't already exist.
func (r *SetupRunner) stepConfigure() error {
	// Load existing values (safe if file doesn't exist yet)
	existing, err := r.Env.ReadEnv()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Interactive mode: prompt for each value
	if r.Interactive {
		return r.stepConfigureInteractive(existing)
	}

	// Non-interactive mode: use CLI flags, then existing, then defaults
	return r.stepConfigureNonInteractive(existing)
}

// stepConfigureInteractive runs the topology-aware setup wizard.
// It uses Select prompts to ask about architecture first, then only shows
// relevant Input prompts based on the deployment topology.
func (r *SetupRunner) stepConfigureInteractive(existing map[string]string) error {
	if !r.Prompter.CanPrompt() {
		return &CLIError{
			Summary:    "--interactive requires a terminal",
			Suggestion: "Run without --interactive, or use --non-interactive for defaults",
		}
	}

	// Helper: resolve default from existing value or fallback
	def := func(key, fallback string) string {
		if v, ok := existing[key]; ok && v != "" {
			return v
		}
		return fallback
	}

	// --- Re-run detection ---
	hasExisting := existing["DATABASE_HOST"] != "" || existing["DATABASE_PASSWORD"] != ""
	if hasExisting {
		fmt.Fprintln(r.Out, "  Existing Heimdall configuration detected.")
		action, err := r.Prompter.Select("What would you like to do?", "",
			[]string{
				"Re-run setup with current config",
				"Edit configuration",
				"Start fresh",
			})
		if err != nil {
			return err
		}

		switch action {
		case 0: // Re-run — keep existing config, just rewrite and continue
			fmt.Fprintln(r.Out, "  Re-running with existing configuration")
			return r.interactiveWriteConfig(existing, existing)
		case 1: // Edit — show prompts with existing values as defaults
			// fall through to the full wizard below (existing values as defaults)
		case 2: // Start fresh — clear existing and run full wizard
			existing = map[string]string{}
		}
	}

	// --- Database topology ---
	fmt.Fprintln(r.Out)
	dbChoice, err := r.Prompter.Select("Database setup", "",
		[]string{
			"Local PostgreSQL (install on this machine)",
			"External PostgreSQL (RDS, Azure, remote server)",
		})
	if err != nil {
		return err
	}

	var dbHost, dbPort, dbUser, dbPassword, dbName string

	switch dbChoice {
	case 0: // Local PostgreSQL — use localhost defaults, only prompt for password
		dbHost = "localhost"
		dbPort = "5432"
		dbUser = "postgres"
		dbName = def("DATABASE_NAME", "heimdall-server-production")

		dbPassword, err = r.interactivePassword(def("DATABASE_PASSWORD", ""))
		if err != nil {
			return err
		}

	case 1: // External PostgreSQL — prompt for all DB fields
		dbHost, err = r.Prompter.Input("Database host", def("DATABASE_HOST", ""))
		if err != nil {
			return err
		}
		dbPort, err = r.Prompter.Input("Database port", def("DATABASE_PORT", "5432"))
		if err != nil {
			return err
		}
		dbUser, err = r.Prompter.Input("Database user", def("DATABASE_USERNAME", "postgres"))
		if err != nil {
			return err
		}
		dbPassword, err = r.interactivePassword(def("DATABASE_PASSWORD", ""))
		if err != nil {
			return err
		}
		dbName, err = r.Prompter.Input("Database name", def("DATABASE_NAME", "heimdall-server-production"))
		if err != nil {
			return err
		}

		// Validate connectivity to external DB before proceeding
		fmt.Fprintln(r.Out)
		fmt.Fprintf(r.Out, "  Testing connection to %s:%s/%s ... ", dbHost, dbPort, dbName)
		port := DefaultDBPort
		if p, parseErr := strconv.Atoi(dbPort); parseErr == nil {
			port = p
		}
		if connErr := r.DB.TestConnection(dbHost, port, dbUser, dbPassword, dbName); connErr != nil {
			fmt.Fprintln(r.Out)
			fmt.Fprintf(r.Out, "  %s\n", Fail(fmt.Sprintf("connection failed: %v", connErr)))
			action, selErr := r.Prompter.Select("Connection failed. What would you do?", "",
				[]string{
					"Abort setup (fix database connectivity first)",
					"Continue anyway (I'll fix it later)",
				})
			if selErr != nil {
				return selErr
			}
			if action == 0 {
				return &CLIError{
					Summary:    "database connection failed",
					Suggestion: "Verify host/port/user/password, then re-run: sudo heimdall-cli setup --interactive",
				}
			}
			fmt.Fprintf(r.Out, "  %s\n", Warn("continuing without verified connection"))
		} else {
			fmt.Fprintf(r.Out, "%s\n", Ok(fmt.Sprintf("connected as %s to %s:%s/%s", dbUser, dbHost, dbPort, dbName)))
		}
	}

	// --- TLS topology ---
	fmt.Fprintln(r.Out)
	tlsChoice, err := r.Prompter.Select("TLS/SSL setup", "",
		[]string{
			"Caddy reverse proxy (automatic HTTPS)",
			"External SSL termination (load balancer, nginx)",
			"BYO certificate (provide cert and key paths)",
			"No TLS (development/testing only)",
		})
	if err != nil {
		return err
	}

	switch tlsChoice {
	case 0: // Caddy — stepTLS runs normally
		// r.SkipTLS stays false

	case 1: // External SSL termination
		r.SkipTLS = true

	case 2: // BYO certificate
		certPath, certErr := r.Prompter.Input("TLS certificate path", def("TLS_CERT", ""))
		if certErr != nil {
			return certErr
		}
		keyPath, keyErr := r.Prompter.Input("TLS private key path", def("TLS_KEY", ""))
		if keyErr != nil {
			return keyErr
		}
		r.TLSCert = certPath
		r.TLSKey = keyPath

	case 3: // No TLS
		r.SkipTLS = true
	}

	// --- Application config ---
	fmt.Fprintln(r.Out)
	externalURL, err := r.Prompter.Input("External URL", def("EXTERNAL_URL", ""))
	if err != nil {
		return err
	}
	adminEmail, err := r.Prompter.Input("Admin email", def("ADMIN_EMAIL", "admin@heimdall.local"))
	if err != nil {
		return err
	}

	// Build the prompted values map
	prompted := map[string]string{
		"DATABASE_HOST":     dbHost,
		"DATABASE_PORT":     dbPort,
		"DATABASE_USERNAME": dbUser,
		"DATABASE_PASSWORD": dbPassword,
		"DATABASE_NAME":     dbName,
		"EXTERNAL_URL":      externalURL,
		"ADMIN_EMAIL":       adminEmail,
	}
	return r.interactiveWriteConfig(existing, prompted)
}

// interactivePassword handles the password prompt with auto-generation for empty input.
func (r *SetupRunner) interactivePassword(existingPass string) (string, error) {
	if existingPass != "" {
		fmt.Fprintln(r.Out, "  Database password: [already set -- press Enter to keep]")
		dbPassword, err := r.Prompter.Password("Database password")
		if err != nil {
			return "", err
		}
		if dbPassword == "" {
			return existingPass, nil
		}
		return dbPassword, nil
	}

	dbPassword, err := ConfirmPassword(r.Prompter, "Database password", true)
	if err != nil {
		return "", err
	}
	if dbPassword == "" {
		b := make([]byte, 33)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("generating password: %w", err)
		}
		dbPassword = hex.EncodeToString(b)
		fmt.Fprintln(r.Out, "  DATABASE_PASSWORD auto-generated")
	}
	return dbPassword, nil
}

// interactiveWriteConfig resolves secrets and derived values, then calls writeConfig.
// prompted contains user-entered values; existing contains previously-saved values.
func (r *SetupRunner) interactiveWriteConfig(existing, prompted map[string]string) error {
	dbHost := prompted["DATABASE_HOST"]
	dbPort := prompted["DATABASE_PORT"]
	dbUser := prompted["DATABASE_USERNAME"]
	dbPassword := prompted["DATABASE_PASSWORD"]
	dbName := prompted["DATABASE_NAME"]
	externalURL := prompted["EXTERNAL_URL"]
	adminEmail := prompted["ADMIN_EMAIL"]

	// Use defaults for empty values (re-run path)
	if dbHost == "" {
		dbHost = "localhost"
	}
	if dbPort == "" {
		dbPort = "5432"
	}
	if dbUser == "" {
		dbUser = "postgres"
	}
	if dbName == "" {
		dbName = "heimdall-server-production"
	}
	if adminEmail == "" {
		adminEmail = "admin@heimdall.local"
	}

	// Auto-generate password if still empty
	if dbPassword == "" {
		b := make([]byte, 33)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generating password: %w", err)
		}
		dbPassword = hex.EncodeToString(b)
		fmt.Fprintln(r.Out, "  DATABASE_PASSWORD auto-generated")
	}

	// Secrets — preserve existing, only generate if missing
	var err error
	jwtSecret := existing["JWT_SECRET"]
	if jwtSecret == "" {
		jwtSecret, err = randomHex(64)
		if err != nil {
			return fmt.Errorf("generating JWT secret: %w", err)
		}
		fmt.Fprintln(r.Out, "  JWT_SECRET auto-generated")
	}
	apiKeySecret := existing["API_KEY_SECRET"]
	if apiKeySecret == "" {
		apiKeySecret, err = randomHex(33)
		if err != nil {
			return fmt.Errorf("generating API key secret: %w", err)
		}
		fmt.Fprintln(r.Out, "  API_KEY_SECRET auto-generated")
	}

	// Derive NGINX_HOST from external URL
	nginxHost := dbHost
	if externalURL != "" {
		h := externalURL
		for _, prefix := range []string{"https://", "http://"} {
			if len(h) > len(prefix) && h[:len(prefix)] == prefix {
				h = h[len(prefix):]
				break
			}
		}
		if idx := strings.IndexAny(h, ":/"); idx >= 0 {
			h = h[:idx]
		}
		nginxHost = h
	}
	if externalURL == "" && nginxHost != "" {
		externalURL = "https://" + nginxHost
	}

	// Show summary of configuration
	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, "  Configuration summary:")
	fmt.Fprintf(r.Out, "    Database: %s@%s:%s/%s\n",
		prompted["DATABASE_USERNAME"], prompted["DATABASE_HOST"],
		prompted["DATABASE_PORT"], prompted["DATABASE_NAME"])
	if prompted["DATABASE_PASSWORD"] != "" {
		fmt.Fprintln(r.Out, "    Password: ********")
	}
	if prompted["EXTERNAL_URL"] != "" {
		fmt.Fprintf(r.Out, "    URL:      %s\n", prompted["EXTERNAL_URL"])
	}
	fmt.Fprintf(r.Out, "    Admin:    %s\n", prompted["ADMIN_EMAIL"])
	fmt.Fprintln(r.Out)

	return r.writeConfig(existing, dbHost, dbPort, dbUser, dbPassword, dbName,
		jwtSecret, apiKeySecret, nginxHost, externalURL, adminEmail)
}

// stepConfigureNonInteractive uses CLI flags, existing values, and defaults.
func (r *SetupRunner) stepConfigureNonInteractive(existing map[string]string) error {
	// Helper: use existing value, then CLI flag, then default
	resolve := func(key, flagVal, fallback string) string {
		if flagVal != "" && flagVal != fallback {
			return flagVal
		}
		if v, ok := existing[key]; ok && v != "" {
			return v
		}
		return fallback
	}

	dbHost := resolve("DATABASE_HOST", r.DBHost, "localhost")
	dbPort := resolve("DATABASE_PORT", fmt.Sprintf("%d", r.DBPort), "5432")
	dbUser := resolve("DATABASE_USERNAME", r.DBUser, "postgres")
	dbName := resolve("DATABASE_NAME", r.DBName, "heimdall-server-production")

	dbPassword := r.DBPassword
	if dbPassword == "" {
		dbPassword = existing["DATABASE_PASSWORD"]
	}
	if dbPassword == "" {
		b := make([]byte, 33)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generating password: %w", err)
		}
		dbPassword = hex.EncodeToString(b)
		fmt.Fprintln(r.Out, "  DATABASE_PASSWORD auto-generated")
	}

	jwtSecret := existing["JWT_SECRET"]
	if jwtSecret == "" {
		var err error
		jwtSecret, err = randomHex(64)
		if err != nil {
			return fmt.Errorf("generating JWT secret: %w", err)
		}
		fmt.Fprintln(r.Out, "  JWT_SECRET auto-generated")
	}

	apiKeySecret := existing["API_KEY_SECRET"]
	if apiKeySecret == "" {
		var err error
		apiKeySecret, err = randomHex(33)
		if err != nil {
			return fmt.Errorf("generating API key secret: %w", err)
		}
		fmt.Fprintln(r.Out, "  API_KEY_SECRET auto-generated")
	}

	port := resolve("PORT", "", DefaultAppPort)
	jwtExpire := resolve("JWT_EXPIRE_TIME", "", "1d")
	nginxHost := resolve("NGINX_HOST", "", "localhost")
	adminEmail := resolve("ADMIN_EMAIL", "", "admin@heimdall.local")

	externalURL := r.ExternalURL
	if externalURL == "" {
		externalURL = existing["EXTERNAL_URL"]
	}
	if externalURL == "" && nginxHost != "" {
		externalURL = "https://" + nginxHost
	}

	_ = port      // used in entries below
	_ = jwtExpire // used in entries below

	return r.writeConfig(existing, dbHost, dbPort, dbUser, dbPassword, dbName,
		jwtSecret, apiKeySecret, nginxHost, externalURL, adminEmail)
}

// writeConfig writes the resolved config to the env file.
func (r *SetupRunner) writeConfig(existing map[string]string,
	dbHost, dbPort, dbUser, dbPassword, dbName,
	jwtSecret, apiKeySecret, nginxHost, externalURL, adminEmail string) error {

	// Preserve values that aren't prompted for
	port := DefaultAppPort
	if v, ok := existing["PORT"]; ok && v != "" {
		port = v
	}
	jwtExpire := "1d"
	if v, ok := existing["JWT_EXPIRE_TIME"]; ok && v != "" {
		jwtExpire = v
	}
	adminPassword := existing["ADMIN_PASSWORD"]

	// Write all keys — matches heimdall-configure.sh output
	entries := map[string]string{
		"NODE_ENV":          "production",
		"PORT":              port,
		"DATABASE_HOST":     dbHost,
		"DATABASE_PORT":     dbPort,
		"DATABASE_USERNAME": dbUser,
		"DATABASE_PASSWORD": dbPassword,
		"DATABASE_NAME":     dbName,
		"JWT_SECRET":        jwtSecret,
		"JWT_EXPIRE_TIME":   jwtExpire,
		"API_KEY_SECRET":    apiKeySecret,
		"NGINX_HOST":        nginxHost,
		"EXTERNAL_URL":      externalURL,
		"ADMIN_EMAIL":       adminEmail,
	}
	if adminPassword != "" {
		entries["ADMIN_PASSWORD"] = adminPassword
	}

	for key, value := range existing {
		if _, managed := entries[key]; !managed {
			entries[key] = value
		}
	}

	if err := r.Env.WriteEnvFile(entries); err != nil {
		return fmt.Errorf("writing env file: %w", err)
	}

	// Store resolved values back to runner so subsequent steps use them
	// (e.g., stepConnectionTest needs the auto-generated DB password).
	r.DBHost = dbHost
	if p, err := strconv.Atoi(dbPort); err == nil {
		r.DBPort = p
	}
	r.DBUser = dbUser
	r.DBPassword = dbPassword
	r.DBName = dbName

	// Set file permissions (matches heimdall-configure.sh)
	r.Exec.Run("chown", "root:heimdall", r.Env.GetEnvFilePath())
	r.Exec.Run("chmod", "0640", r.Env.GetEnvFilePath())

	fmt.Fprintf(r.Out, "  Configuration saved to %s\n", r.Env.GetEnvFilePath())
	return nil
}

// stepPostgresBootstrap delegates PostgreSQL bootstrap to the native
// PostgresBootstrapRunner. Replaces the previous shell-out to
// /usr/libexec/heimdall-server/postgres-setup.sh.
func (r *SetupRunner) stepPostgresBootstrap() error {
	bootstrapper := &PostgresBootstrapRunner{
		Exec:       r.Exec,
		FS:         r.FS,
		Systemd:    r.Systemd,
		Out:        r.Out,
		DBHost:     r.DBHost,
		DBPort:     r.DBPort,
		DBUser:     r.DBUser,
		DBPassword: r.DBPassword,
		DBName:     r.DBName,
	}
	return bootstrapper.Run()
}

// stepConnectionTest runs SELECT 1 against the database.
func (r *SetupRunner) stepConnectionTest() error {
	if err := r.DB.TestConnection(r.DBHost, r.DBPort, r.DBUser, r.DBPassword, r.DBName); err != nil {
		return fmt.Errorf("cannot connect to %s:%d/%s: %w", r.DBHost, r.DBPort, r.DBName, err)
	}
	fmt.Fprintf(r.Out, "  Connected to %s:%d/%s\n", r.DBHost, r.DBPort, r.DBName)
	return nil
}

// stepMigrations runs heimdall-server-db-setup.
func (r *SetupRunner) stepMigrations() error {
	_, exitCode, err := r.Exec.Run("heimdall-server-db-setup")
	if err != nil {
		return fmt.Errorf("running heimdall-server-db-setup: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("heimdall-server-db-setup exited with code %d", exitCode)
	}
	fmt.Fprintln(r.Out, "  Database migrations complete")
	return nil
}

// stepTLS sets up Caddy as a TLS reverse proxy for Heimdall.
// Handles: BYO certificates, private hostnames (internal CA), public
// hostnames (Let's Encrypt ACME), and IP-based (self-signed via openssl).
// tlsStrategy describes which TLS approach to use for Caddy.
type tlsStrategy int

const (
	tlsBYO     tlsStrategy = iota // user-provided certificate
	tlsPrivate                    // private hostname, Caddy internal CA
	tlsPublic                     // public hostname, Let's Encrypt ACME
	tlsIP                         // IP address, self-signed certificate
)

// determineTLSStrategy picks a TLS strategy based on the hostname and flags.
func determineTLSStrategy(host, tlsCert, tlsKey string) tlsStrategy {
	if tlsCert != "" && tlsKey != "" {
		return tlsBYO
	}
	if net.ParseIP(host) != nil {
		return tlsIP
	}
	if isPrivateHostname(host) {
		return tlsPrivate
	}
	return tlsPublic
}

// resolveExternalHost extracts the hostname from EXTERNAL_URL, flags, or the
// system hostname, and ensures EXTERNAL_URL is persisted in backend.env.
func (r *SetupRunner) resolveExternalHost() (host, url string) {
	url = r.ExternalURL
	if url == "" {
		env, _ := r.Env.ReadEnv()
		url = env["EXTERNAL_URL"]
	}

	if url != "" {
		// Strip scheme and port/path: https://foo.example.com:443/bar → foo.example.com
		h := url
		for _, prefix := range []string{"https://", "http://"} {
			if len(h) > len(prefix) && h[:len(prefix)] == prefix {
				h = h[len(prefix):]
				break
			}
		}
		if idx := strings.IndexAny(h, ":/"); idx >= 0 {
			h = h[:idx]
		}
		host = h
	}

	if host == "" {
		out, _, _ := r.Exec.Run("hostname", "-f")
		host = strings.TrimSpace(out)
		if host == "" {
			out, _, _ = r.Exec.Run("hostname")
			host = strings.TrimSpace(out)
		}
		if host == "" {
			host = "localhost"
		}
		url = "https://" + host
	}

	// Persist EXTERNAL_URL if not already set
	env, _ := r.Env.ReadEnv()
	if env["EXTERNAL_URL"] == "" {
		r.Env.WriteEnvKey("EXTERNAL_URL", url)
		fmt.Fprintf(r.Out, "  Set EXTERNAL_URL=%s\n", url)
	}
	return host, url
}

// configureCaddyfile applies the TLS strategy to the Caddyfile and generates
// certificates when needed. Returns an error only on unsafe hostnames.
func (r *SetupRunner) configureCaddyfile(strategy tlsStrategy, host, caddyfileDst string) {
	switch strategy {
	case tlsBYO:
		r.Exec.Run("sed", "-i", fmt.Sprintf("s|^:443 {|%s {|", host), caddyfileDst)
		r.Exec.Run("sed", "-i", fmt.Sprintf(`/reverse_proxy/i\\ttls %s %s`, r.TLSCert, r.TLSKey), caddyfileDst)
		fmt.Fprintf(r.Out, "  Caddy: configured with provided certificate\n")
		fmt.Fprintf(r.Out, "    Cert: %s\n", r.TLSCert)
		fmt.Fprintf(r.Out, "    Key:  %s\n", r.TLSKey)

	case tlsPrivate:
		r.Exec.Run("sed", "-i", `/reverse_proxy/i\\ttls internal`, caddyfileDst)
		fmt.Fprintln(r.Out, "  Caddy: private hostname detected — using internal CA")
		fmt.Fprintln(r.Out, "    Import root CA into browsers to avoid warnings:")
		fmt.Fprintln(r.Out, "    /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt")

	case tlsPublic:
		r.Exec.Run("sed", "-i", fmt.Sprintf("s|^:443 {|%s {|", host), caddyfileDst)
		fmt.Fprintln(r.Out, "  Caddy: public hostname — automatic Let's Encrypt certificate")

	case tlsIP:
		certDir := r.Paths.CertDir
		r.FS.MkdirAll(certDir, 0750)
		r.Exec.Run("chown", "root:caddy", certDir)
		certFile := certDir + "/server.crt"
		keyFile := certDir + "/server.key"
		if !r.FS.Exists(certFile) {
			r.Exec.Run("openssl", "req", "-x509", "-nodes", "-days", "365",
				"-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
				"-keyout", keyFile, "-out", certFile,
				"-subj", fmt.Sprintf("/CN=%s", host),
				"-addext", fmt.Sprintf("subjectAltName=IP:%s,DNS:localhost", host))
			r.Exec.Run("chmod", "640", keyFile)
			r.Exec.Run("chown", "root:caddy", keyFile)
			r.Exec.Run("chmod", "644", certFile)
			fmt.Fprintf(r.Out, "  Generated self-signed cert for %s\n", host)
		}
		r.Exec.Run("sed", "-i", fmt.Sprintf(`/reverse_proxy/i\\ttls %s %s`, certFile, keyFile), caddyfileDst)
		fmt.Fprintln(r.Out, "  Caddy: configured with self-signed cert (IP-based deployment)")
	}
}

func (r *SetupRunner) stepTLS() error {
	// Check if Caddy is available
	_, exitCode, _ := r.Exec.Run("command", "-v", "caddy")
	if exitCode != 0 {
		fmt.Fprintln(r.Out, "  Caddy not installed -- skipping TLS proxy setup")
		fmt.Fprintln(r.Out, "  Install Caddy, then re-run: sudo heimdall-cli setup --skip-db")
		return nil
	}

	caddyfileSrc := r.Paths.LibExecDir + "/heimdall-Caddyfile"
	caddyfileDst := "/etc/caddy/Caddyfile.d/heimdall-server.caddy"

	externalHost, _ := r.resolveExternalHost()

	// Copy Caddyfile template
	if !r.FS.Exists(caddyfileSrc) {
		fmt.Fprintln(r.Out, "  Caddyfile template not found, skipping")
		return nil
	}
	r.Exec.Run("mkdir", "-p", "/etc/caddy/Caddyfile.d")
	if err := r.FS.CopyFile(caddyfileSrc, caddyfileDst); err != nil {
		return fmt.Errorf("copying Caddyfile: %w", err)
	}

	if err := validateHostname(externalHost); err != nil {
		return fmt.Errorf("unsafe hostname %q: %w", externalHost, err)
	}
	if r.TLSCert != "" {
		if err := validateFilePath(r.TLSCert); err != nil {
			return fmt.Errorf("unsafe TLS cert path: %w", err)
		}
	}
	if r.TLSKey != "" {
		if err := validateFilePath(r.TLSKey); err != nil {
			return fmt.Errorf("unsafe TLS key path: %w", err)
		}
	}

	strategy := determineTLSStrategy(externalHost, r.TLSCert, r.TLSKey)
	r.configureCaddyfile(strategy, externalHost, caddyfileDst)

	// Ensure main Caddyfile imports our config
	caddyMain := "/etc/caddy/Caddyfile"
	if r.FS.Exists(caddyMain) {
		mainData, err := r.FS.ReadFile(caddyMain)
		if err == nil && !strings.Contains(string(mainData), "import /etc/caddy/Caddyfile.d/") {
			r.Exec.Run("sh", "-c", `echo 'import /etc/caddy/Caddyfile.d/*.caddy' >> /etc/caddy/Caddyfile`)
		}
	}

	// Install internal CA root cert into system trust.
	// Use update-ca-trust instead of 'caddy trust' which hangs waiting for
	// interactive password input on some systems.
	r.Exec.Run("update-ca-trust")

	// Enable and start Caddy (use systemctl directly to avoid blocking)
	r.Systemd.EnableNow("caddy")
	r.Exec.Run("systemctl", "restart", "caddy")
	fmt.Fprintln(r.Out, "  Caddy: enabled and running")

	// SELinux: allow Caddy to proxy to backend
	_, exitCode, _ = r.Exec.Run("command", "-v", "setsebool")
	if exitCode == 0 {
		r.Exec.Run("setsebool", "-P", "httpd_can_network_connect", "on")
		fmt.Fprintln(r.Out, "  SELinux: httpd_can_network_connect enabled")
	}

	return nil
}

// filePathPattern restricts file paths to safe characters for use in sed
// arguments. Only allows alphanumeric, dots, underscores, hyphens, and slashes.
var filePathPattern = regexp.MustCompile(`^/[a-zA-Z0-9._/-]+$`)

// validateFilePath checks that a file path is absolute and contains only
// safe characters for interpolation into sed commands.
func validateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	if !filePathPattern.MatchString(path) {
		return fmt.Errorf("path contains unsafe characters: %s", path)
	}
	if strings.Contains(path, "..") {
		return fmt.Errorf("path contains traversal: %s", path)
	}
	return nil
}

// hostnamePattern validates that a hostname or IP is safe for use in sed
// regex patterns and openssl certificate subjects.
var hostnamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,252}[a-zA-Z0-9]$|^[a-zA-Z0-9]$`)

// validateHostname checks that a hostname is well-formed and safe for use
// in sed commands and openssl -subj arguments.
func validateHostname(host string) error {
	if host == "" {
		return fmt.Errorf("hostname is empty")
	}
	if !hostnamePattern.MatchString(host) {
		return fmt.Errorf("invalid hostname: contains unsafe characters")
	}
	return nil
}

// isPrivateHostname returns true for hostnames that need Caddy's internal CA
// instead of Let's Encrypt ACME (which can't validate private names).
func isPrivateHostname(host string) bool {
	privateSuffixes := []string{
		".internal", ".local", ".lan", ".localdomain",
		".home.arpa", ".corp", ".private", ".test",
	}
	for _, suffix := range privateSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	// Single-label hostname (no dots) is private
	if !strings.Contains(host, ".") {
		return true
	}
	return false
}

// stepSecurityPolicies configures SELinux, fapolicyd, and firewalld.
// Reads PORT from backend.env to register the correct port (not hardcoded 3000).
func (r *SetupRunner) stepSecurityPolicies() {
	// Read the actual port from config
	env, _ := r.Env.ReadEnv()
	port := envDefault(env, "PORT", DefaultAppPort)

	// SELinux: register port type (try -a first, fall back to -m)
	_, exitCode, _ := r.Exec.Run("command", "-v", "semanage")
	if exitCode == 0 {
		_, rc, _ := r.Exec.Run("semanage", "port", "-a", "-t", "heimdall_server_port_t", "-p", "tcp", port)
		if rc != 0 {
			r.Exec.Run("semanage", "port", "-m", "-t", "heimdall_server_port_t", "-p", "tcp", port)
		}
		fmt.Fprintf(r.Out, "  SELinux: port %s registered\n", port)
	}
	_, exitCode, _ = r.Exec.Run("command", "-v", "restorecon")
	if exitCode == 0 {
		r.Exec.Run("restorecon", "-R", r.Paths.AppDir, r.Paths.ConfigDir, r.Paths.DataDir)
		fmt.Fprintln(r.Out, "  SELinux: file contexts applied")
	}

	// fapolicyd
	fapScript := r.Paths.LibExecDir + "/fapolicyd-trust.sh"
	if r.FS.Exists(fapScript) {
		r.Exec.Run(fapScript, "add")
		fmt.Fprintln(r.Out, "  fapolicyd: bundled binaries trusted")
	} else {
		fmt.Fprintln(r.Out, "  fapolicyd: not installed (skipped)")
	}

	// firewalld
	active, _ := r.Systemd.IsActive("firewalld")
	if active {
		if r.SkipTLS {
			r.Exec.Run("firewall-cmd", "--permanent", fmt.Sprintf("--add-port=%s/tcp", port))
			fmt.Fprintf(r.Out, "  firewalld: port %s/tcp enabled\n", port)
		} else {
			r.Exec.Run("firewall-cmd", "--permanent", "--add-service=https")
			fmt.Fprintln(r.Out, "  firewalld: HTTPS (443) enabled")
		}
		r.Exec.Run("firewall-cmd", "--reload")
	} else {
		fmt.Fprintln(r.Out, "  firewalld: not running (skipped)")
	}

	// File permission hardening
	r.Exec.Run("chown", "root:heimdall", r.Paths.ConfigDir)
	r.Exec.Run("chmod", "0750", r.Paths.ConfigDir)
	r.Exec.Run("chown", "-R", "heimdall:heimdall", r.Paths.DataDir)
	r.Exec.Run("chmod", "0750", r.Paths.DataDir)
	r.Exec.Run("chmod", "0700", r.Paths.DataDir+"/backups")
	r.Exec.Run("chown", "-R", "heimdall:heimdall", r.Paths.LogDir)
	r.Exec.Run("chmod", "0750", r.Paths.LogDir)
	fmt.Fprintln(r.Out, "  File permissions hardened")
}

// stepStartService enables and starts the service.
// Validates that required config exists before attempting to start.
func (r *SetupRunner) stepStartService() error {
	// Verify critical config exists before starting (matches heimdall-server.sh)
	env, _ := r.Env.ReadEnv()
	if env["DATABASE_PASSWORD"] == "" {
		return fmt.Errorf("DATABASE_PASSWORD is not set in %s — run setup first", r.Env.GetEnvFilePath())
	}

	if err := r.Systemd.EnableNow(ServiceName); err != nil {
		return fmt.Errorf("enabling service: %w", err)
	}
	fmt.Fprintln(r.Out, "  Service enabled and started")
	return nil
}

func (r *SetupRunner) printCompletionBanner() {
	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, "==========================================")
	fmt.Fprintln(r.Out, " Heimdall server is running.")
	if r.ExternalURL != "" {
		fmt.Fprintf(r.Out, " Open: %s\n", r.ExternalURL)
	}
	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, " Useful commands:")
	fmt.Fprintf(r.Out, "   systemctl status  %s\n", ServiceName)
	fmt.Fprintf(r.Out, "   journalctl -u     %s\n", ServiceName)

	cloud := r.detectCloud()
	r.printCloudHint(cloud)

	fmt.Fprintln(r.Out, "==========================================")
}

// detectCloud checks cloud metadata endpoints.
func (r *SetupRunner) detectCloud() string {
	// EC2
	out, exitCode, _ := r.Exec.Run("curl", "-sf", "-m", "2", "http://169.254.169.254/latest/meta-data/instance-id")
	if exitCode == 0 && out != "" {
		return "ec2"
	}
	// Azure
	out, exitCode, _ = r.Exec.Run("curl", "-sf", "-m", "2", "-H", "Metadata:true",
		"http://169.254.169.254/metadata/instance?api-version=2021-02-01")
	if exitCode == 0 && out != "" {
		return "azure"
	}
	// GCP
	out, exitCode, _ = r.Exec.Run("curl", "-sf", "-m", "2", "-H", "Metadata-Flavor: Google",
		"http://metadata.google.internal/")
	if exitCode == 0 && out != "" {
		return "gcp"
	}
	return "bare-metal"
}

func (r *SetupRunner) printCloudHint(cloud string) {
	switch cloud {
	case "ec2":
		fmt.Fprintln(r.Out)
		fmt.Fprintln(r.Out, "  NOTE: Detected AWS EC2 instance.")
		fmt.Fprintln(r.Out, "  Ensure your Security Group allows inbound HTTPS (TCP 443).")
	case "azure":
		fmt.Fprintln(r.Out)
		fmt.Fprintln(r.Out, "  NOTE: Detected Azure VM.")
		fmt.Fprintln(r.Out, "  Ensure your Network Security Group (NSG) allows inbound HTTPS (TCP 443).")
	case "gcp":
		fmt.Fprintln(r.Out)
		fmt.Fprintln(r.Out, "  NOTE: Detected GCP VM.")
		fmt.Fprintln(r.Out, "  Ensure your VPC firewall rule allows inbound HTTPS (TCP 443).")
	}
}

// isLocalHost returns true if the host refers to localhost.
func isLocalHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" || h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// randomHex generates n random bytes and returns them hex-encoded.
// Uses crypto/rand which delegates to BoringSSL under GOEXPERIMENT=boringcrypto (FIPS).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
