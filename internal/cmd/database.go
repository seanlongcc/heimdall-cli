package cmd

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// DBConfig holds database connection parameters extracted from the environment.
type DBConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
	SSLCA    string
	SSLCert  string
	SSLKey   string
}

// PortStr returns the port as a string, suitable for passing to CLI tools
// like pg_dump and psql.
func (c DBConfig) PortStr() string {
	return strconv.Itoa(c.Port)
}

// PgEnv returns the environment map for passing PGPASSWORD to psql/pg_dump.
func (c DBConfig) PgEnv() map[string]string {
	env := map[string]string{"PGPASSWORD": c.Password, "PGSSLMODE": c.SSLMode}
	if env["PGSSLMODE"] == "" {
		env["PGSSLMODE"] = "disable"
	}
	for key, value := range map[string]string{"PGSSLROOTCERT": c.SSLCA, "PGSSLCERT": c.SSLCert, "PGSSLKEY": c.SSLKey} {
		if value != "" {
			env[key] = value
		}
	}
	return env
}

// ExtractDBConfig reads database connection parameters from the environment map,
// applying defaults for missing values.
func ExtractDBConfig(env map[string]string) DBConfig {
	cfg := DBConfig{
		Host:     envDefault(env, "DATABASE_HOST", "localhost"),
		User:     envDefault(env, "DATABASE_USERNAME", "postgres"),
		Password: env["DATABASE_PASSWORD"],
		DBName:   envDefault(env, "DATABASE_NAME", "heimdall-server-production"),
	}
	cfg.Port = DefaultDBPort
	if p, err := strconv.Atoi(envDefault(env, "DATABASE_PORT", "5432")); err == nil {
		cfg.Port = p
	}
	return cfg
}

// resolveDBConfig validates the effective endpoint before any SQL or configuration
// changes. A URL and individual values must describe the same database.
func resolveDBConfig(env map[string]string) (DBConfig, error) {
	values := make(map[string]string, len(env))
	for key, value := range env {
		values[key] = value
	}
	if raw := env["DATABASE_URL"]; raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() == "" || u.User == nil || strings.TrimPrefix(u.Path, "/") == "" {
			return DBConfig{}, fmt.Errorf("DATABASE_URL must be a PostgreSQL URL with host, user and database")
		}
		// Heimdall's AppConfig parser keeps percent escapes literal and uses
		// the first password/name segment. Do not silently use decoded credentials.
		userinfo := strings.SplitN(strings.TrimPrefix(raw, u.Scheme+"://"), "@", 2)[0]
		parts := strings.Split(userinfo, ":")
		password := ""
		if len(parts) > 1 {
			password = parts[1]
		}
		name := strings.SplitN(strings.TrimPrefix(u.EscapedPath(), "/"), "/", 2)[0]
		components := map[string]string{"DATABASE_HOST": u.Hostname(), "DATABASE_PORT": u.Port(), "DATABASE_USERNAME": parts[0], "DATABASE_PASSWORD": password, "DATABASE_NAME": name}
		if components["DATABASE_PORT"] == "" {
			components["DATABASE_PORT"] = "5432"
		}
		for key, value := range components {
			if saved := env[key]; saved != "" && saved != value {
				return DBConfig{}, fmt.Errorf("%s conflicts with DATABASE_URL; update the URL and individual settings together", key)
			}
			values[key] = value
		}
	}
	if p := values["DATABASE_PORT"]; p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return DBConfig{}, fmt.Errorf("DATABASE_PORT must be between 1 and 65535")
		}
	}
	cfg := ExtractDBConfig(values)
	cfg.SSLMode = "disable"
	if ssl := env["DATABASE_SSL"]; ssl != "" && !strings.EqualFold(ssl, "false") {
		cfg.SSLMode = "verify-full"
		if strings.EqualFold(env["DATABASE_SSL_INSECURE"], "true") {
			cfg.SSLMode = "require"
		}
		cfg.SSLCA, cfg.SSLCert, cfg.SSLKey = env["DATABASE_SSL_CA"], env["DATABASE_SSL_CERT"], env["DATABASE_SSL_KEY"]
	}
	return cfg, nil
}
