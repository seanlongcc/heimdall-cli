package cmd

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newSetPortRunner() (*SetPortRunner, *FakeExecRunner, *FakeEnvManager, *FakeSystemdRunner, *bytes.Buffer) {
	out := new(bytes.Buffer)
	exec := &FakeExecRunner{Results: map[string]FakeExecResult{}}
	env := &FakeEnvManager{Env: map[string]string{"PORT": "3000"}}
	systemd := &FakeSystemdRunner{ActiveServices: map[string]bool{}, Properties: map[string]string{}}
	return &SetPortRunner{
		Exec:    exec,
		Env:     env,
		Systemd: systemd,
		Out:     out,
		ErrOut:  new(bytes.Buffer),
	}, exec, env, systemd, out
}

func TestSetPort_InvalidPortZero(t *testing.T) {
	runner, _, _, _, _ := newSetPortRunner()
	err := runner.Run("0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port must be 1-65535")
}

func TestSetPort_InvalidPort65536(t *testing.T) {
	runner, _, _, _, _ := newSetPortRunner()
	err := runner.Run("65536")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port must be 1-65535")
}

func TestSetPort_InvalidPortNotNumber(t *testing.T) {
	runner, _, _, _, _ := newSetPortRunner()
	err := runner.Run("abc")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port must be 1-65535")
}

func TestSetPort_UpdatesEnvFile(t *testing.T) {
	runner, _, env, _, out := newSetPortRunner()
	err := runner.Run("8080")
	require.NoError(t, err)
	assert.Equal(t, "8080", env.Env["PORT"])
	// Verify output shows old and new port
	assert.Contains(t, out.String(), "PORT=8080 (was 3000)")
}

func TestSetPort_SELinuxDisabledAndFirewall(t *testing.T) {
	runner, exec, _, _, _ := newSetPortRunner()
	err := runner.Run("8080")
	require.NoError(t, err)

	foundSemanage := false
	foundFirewall := false
	for _, call := range exec.Calls {
		if call.Name == "semanage" {
			foundSemanage = true
			assert.Contains(t, call.Args, "heimdall_server_port_t", "semanage should use heimdall_server_port_t")
			assert.Contains(t, call.Args, "8080", "semanage should use the new port")
		}
		if call.Name == "firewall-cmd" && len(call.Args) > 0 {
			for _, arg := range call.Args {
				if arg == "--add-port=8080/tcp" {
					foundFirewall = true
				}
			}
		}
	}
	assert.False(t, foundSemanage, "disabled SELinux requires no registration")
	assert.True(t, foundFirewall, "should call firewall-cmd --add-port=8080/tcp")
}

func TestSetPort_RestartsService(t *testing.T) {
	runner, _, _, systemd, _ := newSetPortRunner()
	err := runner.Run("8080")
	require.NoError(t, err)
	assert.Contains(t, systemd.Actions, "restart:"+ServiceName)
}

func TestSetPortBundledRollbackAndConfigDelegation(t *testing.T) {
	for _, failure := range []string{"validate", "restart", "reload", "none"} {
		t.Run(failure, func(t *testing.T) {
			setup := bundledSetupFixture(t)
			fs := setup.FS.(*FakeFileSystem)
			exec := setup.Exec.(*FakeExecRunner)
			fs.Files[setup.Paths.ConfigDir+"/caddy/Caddyfile"] = []byte("old config\n")
			sd := &portFailureSystemd{FakeSystemdRunner: setup.Systemd.(*FakeSystemdRunner), failure: failure}
			sd.ActiveServices[bundledCaddyService] = true
			if failure == "validate" {
				exec.Results["runuser -u heimdall-caddy"] = FakeExecResult{ExitCode: 1}
			}
			port := &SetPortRunner{Exec: exec, Env: setup.Env, Systemd: sd, FS: fs, Paths: setup.Paths, Out: setup.Out}
			cfg := &ConfigRunner{Env: setup.Env, Out: setup.Out, Port: port}
			err := cfg.Set("PORT", "4567")
			if failure == "none" {
				require.NoError(t, err)
				require.Equal(t, "4567", setup.Env.(*FakeEnvManager).Env["PORT"])
				require.Contains(t, string(fs.Files[setup.Paths.ConfigDir+"/caddy/Caddyfile"]), "127.0.0.1:4567")
			} else {
				require.Error(t, err)
				require.Equal(t, "3210", setup.Env.(*FakeEnvManager).Env["PORT"])
				require.Equal(t, "old config\n", string(fs.Files[setup.Paths.ConfigDir+"/caddy/Caddyfile"]))
			}
			if failure == "validate" {
				require.Empty(t, sd.Actions)
			}
		})
	}
}

type portFailureSystemd struct {
	*FakeSystemdRunner
	failure string
}

func (s *portFailureSystemd) Restart(unit string) error {
	if s.failure == "restart" {
		s.failure = ""
		return fmt.Errorf("restart failed")
	}
	return s.FakeSystemdRunner.Restart(unit)
}
func (s *portFailureSystemd) Reload(unit string) error {
	if s.failure == "reload" {
		s.failure = ""
		return fmt.Errorf("reload failed")
	}
	return s.FakeSystemdRunner.Reload(unit)
}
