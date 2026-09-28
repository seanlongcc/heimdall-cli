package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newSecurityTestRunner(env map[string]string) (*SetupRunner, *bytes.Buffer) {
	out := new(bytes.Buffer)
	r := &SetupRunner{
		Exec: &FakeExecRunner{
			Results: make(map[string]FakeExecResult),
		},
		Systemd: &FakeSystemdRunner{
			ActiveServices: make(map[string]bool),
			Properties:     make(map[string]string),
		},
		Env:   &FakeEnvManager{Env: env},
		FS:    NewFakeFileSystem(),
		Out:   out,
		Paths: DefaultPaths(),
	}
	return r, out
}

func TestStepSecurityPolicies_SELinuxPresent(t *testing.T) {
	r, out := newSecurityTestRunner(map[string]string{"PORT": "3000"})
	// semanage and restorecon are available
	r.Exec.(*FakeExecRunner).Results[`sh -c command -v "$1"`] = FakeExecResult{ExitCode: 0}

	r.stepSecurityPolicies()

	output := out.String()
	assert.Contains(t, output, "SELinux: port 3000 registered")
	assert.Contains(t, output, "SELinux: file contexts applied")

	// Verify semanage was called with correct port
	calls := r.Exec.(*FakeExecRunner).Calls
	foundSemanage := false
	for _, c := range calls {
		if c.Name == "semanage" {
			foundSemanage = true
			assert.Contains(t, c.Args, "3000")
		}
	}
	assert.True(t, foundSemanage, "semanage should be called")
}

func TestStepSecurityPolicies_SELinuxAbsent(t *testing.T) {
	r, out := newSecurityTestRunner(map[string]string{"PORT": "3000"})
	// semanage not available
	r.Exec.(*FakeExecRunner).Results[`sh -c command -v "$1"`] = FakeExecResult{ExitCode: 1}

	r.stepSecurityPolicies()

	output := out.String()
	assert.NotContains(t, output, "SELinux: port")
	assert.NotContains(t, output, "file contexts")
}

func TestStepSecurityPolicies_CustomPort(t *testing.T) {
	r, out := newSecurityTestRunner(map[string]string{"PORT": "8443"})
	r.Exec.(*FakeExecRunner).Results[`sh -c command -v "$1"`] = FakeExecResult{ExitCode: 0}
	r.SkipTLS = true
	r.Systemd.(*FakeSystemdRunner).ActiveServices["firewalld"] = true

	r.stepSecurityPolicies()

	output := out.String()
	assert.Contains(t, output, "SELinux: port 8443 registered")
	assert.Contains(t, output, "firewalld: port 8443/tcp enabled")

	// Verify semanage used 8443, not 3000
	for _, c := range r.Exec.(*FakeExecRunner).Calls {
		if c.Name == "semanage" {
			assert.Contains(t, c.Args, "8443", "semanage should use PORT from env, not hardcoded 3000")
			assert.NotContains(t, c.Args, "3000")
		}
		if c.Name == "firewall-cmd" {
			for _, arg := range c.Args {
				if arg == "--add-port=8443/tcp" {
					// correct
				}
				assert.NotEqual(t, "--add-port=3000/tcp", arg, "firewalld should use PORT from env")
			}
		}
	}
}

func TestStepSecurityPolicies_DefaultPort(t *testing.T) {
	// No PORT in env — should default to 3000
	r, out := newSecurityTestRunner(map[string]string{})
	r.Exec.(*FakeExecRunner).Results[`sh -c command -v "$1"`] = FakeExecResult{ExitCode: 0}

	r.stepSecurityPolicies()

	assert.Contains(t, out.String(), "port 3000 registered")
}

func TestStepSecurityPolicies_FapolicydPresent(t *testing.T) {
	r, out := newSecurityTestRunner(map[string]string{})
	// fapolicyd trust script exists
	fapScript := DefaultPaths().LibExecDir + "/fapolicyd-trust.sh"
	r.FS.(*FakeFileSystem).Files[fapScript] = []byte("#!/bin/bash")

	r.stepSecurityPolicies()

	assert.Contains(t, out.String(), "fapolicyd: bundled binaries trusted")

	// Verify script was called with "add"
	foundFap := false
	for _, c := range r.Exec.(*FakeExecRunner).Calls {
		if c.Name == fapScript {
			foundFap = true
			assert.Equal(t, []string{"add"}, c.Args)
		}
	}
	assert.True(t, foundFap, "fapolicyd trust script should be called")
}

func TestStepSecurityPolicies_FapolicydAbsent(t *testing.T) {
	r, out := newSecurityTestRunner(map[string]string{})
	// No fapolicyd script

	r.stepSecurityPolicies()

	assert.Contains(t, out.String(), "fapolicyd: not installed (skipped)")
}

func TestStepSecurityPolicies_FirewalldActiveWithTLS(t *testing.T) {
	r, out := newSecurityTestRunner(map[string]string{})
	r.Systemd.(*FakeSystemdRunner).ActiveServices["firewalld"] = true
	r.SkipTLS = false

	r.stepSecurityPolicies()

	assert.Contains(t, out.String(), "firewalld: HTTPS (443) enabled")
}

func TestStepSecurityPolicies_FirewalldActiveSkipTLS(t *testing.T) {
	r, out := newSecurityTestRunner(map[string]string{"PORT": "3000"})
	r.Systemd.(*FakeSystemdRunner).ActiveServices["firewalld"] = true
	r.SkipTLS = true

	r.stepSecurityPolicies()

	assert.Contains(t, out.String(), "firewalld: port 3000/tcp enabled")
}

func TestStepSecurityPolicies_FirewalldNotRunning(t *testing.T) {
	r, out := newSecurityTestRunner(map[string]string{})
	// firewalld not active (default in FakeSystemdRunner)

	r.stepSecurityPolicies()

	assert.Contains(t, out.String(), "firewalld: not running (skipped)")
}

func TestStepSecurityPolicies_FilePermissions(t *testing.T) {
	r, _ := newSecurityTestRunner(map[string]string{})

	r.stepSecurityPolicies()

	// Verify chmod/chown called for config, data, log dirs
	calls := r.Exec.(*FakeExecRunner).Calls
	chownCalls := 0
	chmodCalls := 0
	for _, c := range calls {
		if c.Name == "chown" {
			chownCalls++
		}
		if c.Name == "chmod" {
			chmodCalls++
		}
	}
	assert.GreaterOrEqual(t, chownCalls, 3, "should chown config, data, and log dirs")
	assert.GreaterOrEqual(t, chmodCalls, 4, "should chmod config dir, data dir, backups dir, and log dir")
}
