package cmd

import (
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"
)

// SetPortRunner holds dependencies for the set-port command.
type SetPortRunner struct {
	FS        FileSystem
	Paths     Paths
	Exec      ExecRunner
	Env       EnvManager
	Systemd   SystemdRunner
	Out       io.Writer
	ErrOut    io.Writer
	CheckRoot func() error
}

// Run executes the set-port logic.
func (r *SetPortRunner) Run(portStr string) (err error) {
	if r.CheckRoot != nil {
		if err := r.CheckRoot(); err != nil {
			return err
		}
	}
	if r.FS == nil {
		r.FS = &osFileSystem{}
	}
	if r.Paths.AppDir == "" {
		r.Paths = DefaultPaths()
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("port must be 1-65535")
	}

	env, err := r.Env.ReadEnv()
	if err != nil {
		return fmt.Errorf("failed to read env: %w", err)
	}
	oldPort := env["PORT"]
	if oldPort == "" {
		oldPort = DefaultAppPort
	}

	bundled, err := r.Paths.hasRuntime(r.FS)
	if err != nil {
		return err
	}
	var proxy *caddyUpdate
	var before savedFile
	if bundled {
		before, err = snapshotFile(r.FS, r.Env.GetEnvFilePath())
		if err != nil {
			return err
		}
		if err := checkOwnedPort(r.Exec, r.Systemd, p, ServiceName, false); err != nil {
			return err
		}
		if env["HEIMDALL_PROXY_MODE"] == "bundled" {
			candidate := make(map[string]string, len(env))
			for key, value := range env {
				candidate[key] = value
			}
			candidate["PORT"] = portStr
			setup := &SetupRunner{Paths: r.Paths, Exec: r.Exec, FS: r.FS, Systemd: r.Systemd, Env: r.Env, Out: r.Out}
			proxy, err = setup.prepareBundledCaddy(candidate)
			if err != nil {
				return err
			}
		}
	}
	wrote, restarted := false, false
	defer func() {
		if err == nil || !wrote {
			return
		}
		var rollback []error
		rollback = append(rollback, r.Env.WriteEnvFile(env))
		if bundled {
			if _, ok := r.Env.(*FileEnvManager); ok {
				rollback = append(rollback, before.restore(r.FS))
			}
		}
		if proxy != nil {
			rollback = append(rollback, proxy.rollback())
		}
		if restarted {
			rollback = append(rollback, r.Systemd.Restart(ServiceName))
		}
		err = errors.Join(append([]error{err}, rollback...)...)
	}()
	wrote = true
	if err := r.Env.WriteEnvKey("PORT", portStr); err != nil {
		return fmt.Errorf("failed to update env: %w", err)
	}
	fmt.Fprintf(r.Out, "Config:    PORT=%s (was %s)\n", portStr, oldPort)

	// SELinux
	r.Exec.Run("semanage", "port", "-a", "-t", "heimdall_server_port_t", "-p", "tcp", portStr)
	r.Exec.Run("semanage", "port", "-m", "-t", "heimdall_server_port_t", "-p", "tcp", portStr)
	fmt.Fprintf(r.Out, "SELinux:   port %s registered\n", portStr)

	// firewalld
	r.Exec.Run("firewall-cmd", "--permanent", "--add-port="+portStr+"/tcp")
	r.Exec.Run("firewall-cmd", "--reload")
	fmt.Fprintf(r.Out, "firewalld: port %s opened\n", portStr)

	// Restart
	fmt.Fprintln(r.Out)
	fmt.Fprintln(r.Out, "Restarting service...")
	restarted = true
	if err := r.Systemd.Restart(ServiceName); err != nil {
		return fmt.Errorf("failed to restart service: %w", err)
	}
	if proxy != nil {
		if err := proxy.apply(); err != nil {
			return err
		}
	}
	if bundled && env["HEIMDALL_PROXY_MODE"] == "external" {
		fmt.Fprintf(r.Out, "Backend address: http://127.0.0.1:%s\n", portStr)
	}
	fmt.Fprintf(r.Out, "Done. Heimdall now listening on port %s.\n", portStr)

	return nil
}

// NewSetPortCmd creates the set-port command.
func NewSetPortCmd(runner *SetPortRunner) *cobra.Command {
	production := runner == nil
	if runner == nil {
		runner = &SetPortRunner{
			FS: &osFileSystem{}, Paths: DefaultPaths(),
			Exec:      &execRunner{},
			Env:       NewFileEnvManager(),
			Systemd:   &systemdRunner{},
			CheckRoot: requireRoot,
		}
	}
	return &cobra.Command{
		Use:   "set-port <port>",
		Short: "Change the listen port (updates config, SELinux, firewalld)",
		Long: `Change the port that Heimdall Server listens on. This command updates
three system layers in a single operation:

  1. Config:    Sets PORT in backend.env to the new value
  2. SELinux:   Registers the new port as heimdall_server_port_t so the
               service is allowed to bind under enforcing mode
  3. firewalld: Opens the new port in the permanent firewall rules

After updating all layers, the service is automatically restarted.
The port must be between 1 and 65535. Requires root privileges.`,
		Example: `  # Change the listen port to 8443
  sudo heimdall-cli set-port 8443

  # Change to a non-standard port
  sudo heimdall-cli set-port 9000`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if production {
				runner.Paths = commandPaths(cmd)
				runner.Env = &FileEnvManager{Path: runner.Paths.EnvFile}
			}
			initIO(&runner.Out, &runner.ErrOut, cmd)
			return runner.Run(args[0])
		},
	}
}
