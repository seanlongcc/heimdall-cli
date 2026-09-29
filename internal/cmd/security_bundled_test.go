package cmd

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

// Security fixtures supply the root-owned metadata that the general fake omits.
type securityFS struct {
	*FakeFileSystem
	badPath    string
	badMode    os.FileMode
	uid        uint32
	failRename bool
}
type securityInfo struct {
	os.FileInfo
	mode os.FileMode
	uid  uint32
}

func (i securityInfo) Mode() os.FileMode { return i.mode }
func (i securityInfo) Sys() any          { return &syscall.Stat_t{Uid: i.uid, Gid: 0, Nlink: 1} }
func (f *securityFS) Lstat(path string) (os.FileInfo, error) {
	i, e := f.FakeFileSystem.Lstat(path)
	if e != nil {
		return i, e
	}
	mode := os.FileMode(0600)
	if i.IsDir() {
		mode = os.ModeDir | 0751
	}
	uid := uint32(0)
	if path == f.badPath {
		mode = f.badMode
		uid = f.uid
	}
	return securityInfo{i, mode, uid}, nil
}
func (f *securityFS) Rename(old, new string) error {
	if f.failRename {
		return fmt.Errorf("rename denied")
	}
	return f.FakeFileSystem.Rename(old, new)
}
func enableSELinux(r *SetupRunner) (*FakeFileSystem, *FakeExecRunner) {
	fs := r.FS.(*FakeFileSystem)
	fs.Files["/sys/fs/selinux/enforce"] = []byte("1\n")
	fs.Dirs[r.Paths.ConfigDir] = true
	r.FS = &securityFS{FakeFileSystem: fs}
	ex := r.Exec.(*FakeExecRunner)
	ex.Results["semanage port -l"] = FakeExecResult{Stdout: "SELinux Port Type              Proto    Port Number\nhttp_port_t tcp 80, 443\nunreserved_port_t tcp 1024-65535\n"}
	return fs, ex
}
func TestBundledUpgradeMigrationGate(t *testing.T) {
	for _, mode := range []string{"success", "skip-db", "reconfigure", "failed"} {
		t.Run(mode, func(t *testing.T) {
			r := bundledSetupFixture(t)
			fs := r.FS.(*FakeFileSystem)
			marker := r.Paths.ConfigDir + "/upgrade-pending"
			fs.Files[marker] = []byte("pending\n")
			r.FS = &securityFS{FakeFileSystem: fs}
			sd := r.Systemd.(*FakeSystemdRunner)
			switch mode {
			case "skip-db":
				r.SkipDB = true
			case "reconfigure":
				r.Reconfigure = true
			case "failed":
				r.Exec.(*FakeExecRunner).Results["heimdall-server-db-setup"] = FakeExecResult{ExitCode: 1}
			}
			err := r.Run()
			if mode == "failed" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if mode == "success" {
				require.False(t, fs.Exists(marker))
				require.True(t, sd.ActiveServices[ServiceName])
			} else {
				require.True(t, fs.Exists(marker))
				require.NotContains(t, sd.Actions, "restart:"+ServiceName)
				require.False(t, sd.ActiveServices[ServiceName])
			}
		})
	}
}
func TestBundledSELinuxConflictsPrecedeMutation(t *testing.T) {
	for _, line := range []string{"ssh_port_t tcp 3210", "other_port_t tcp 55000-56000", "other_port_t tcp 81, 443, 8443"} {
		t.Run(line, func(t *testing.T) {
			r := bundledSetupFixture(t)
			fs, ex := enableSELinux(r)
			ex.Results["semanage port -l"] = FakeExecResult{Stdout: line + "\n"}
			before, _ := r.Env.ReadEnv()
			beforeFiles := map[string]string{}
			for p, d := range fs.Files {
				beforeFiles[p] = string(d)
			}
			err := r.Run()
			require.Error(t, err)
			require.Contains(t, err.Error(), "SELinux")
			require.Equal(t, before, r.Env.(*FakeEnvManager).Env)
			require.Empty(t, r.Systemd.(*FakeSystemdRunner).Actions)
			after := map[string]string{}
			for p, d := range fs.Files {
				after[p] = string(d)
			}
			require.Equal(t, beforeFiles, after)
			for _, c := range ex.Calls {
				if c.Name == "semanage" {
					require.NotContains(t, c.Args, "-m")
				}
				require.NotEqual(t, "chown", c.Name)
			}
		})
	}
}
func TestBundledSELinuxLedgerAndFailures(t *testing.T) {
	for _, mode := range []string{"new", "compatible", "query failure", "add failure", "unsafe ledger", "rename failure"} {
		t.Run(mode, func(t *testing.T) {
			r := bundledSetupFixture(t)
			r.SkipDB = true
			r.SkipTLS = true
			fs, ex := enableSELinux(r)
			ledger := r.Paths.ConfigDir + "/selinux-ports"
			switch mode {
			case "compatible":
				ex.Results["semanage port -l"] = FakeExecResult{Stdout: "heimdall_server_port_t tcp 3000, 3200-3220\n"}
			case "query failure":
				ex.Results["semanage port -l"] = FakeExecResult{ExitCode: 1}
			case "add failure":
				ex.Results["semanage port -a"] = FakeExecResult{ExitCode: 1}
			case "unsafe ledger":
				fs.Files[ledger] = []byte("http_port_t tcp 8443\n")
				r.FS.(*securityFS).badPath = ledger
				r.FS.(*securityFS).badMode = 0666
			case "rename failure":
				r.FS.(*securityFS).failRename = true
			}
			err := r.Run()
			if mode == "new" {
				require.NoError(t, err)
				require.Equal(t, "heimdall_server_port_t tcp 3210\n", string(fs.Files[ledger]))
			} else if mode == "compatible" {
				require.NoError(t, err)
				require.False(t, fs.Exists(ledger))
			} else {
				require.Error(t, err)
				require.NotContains(t, r.Systemd.(*FakeSystemdRunner).Actions, "restart:"+ServiceName)
			}
			for _, c := range ex.Calls {
				if c.Name == "semanage" {
					require.NotContains(t, c.Args, "-m")
				}
			}
		})
	}
}
func TestSetPortSELinuxConflictAndFailedAddPreserveConfig(t *testing.T) {
	for _, failure := range []string{"conflict", "add"} {
		t.Run(failure, func(t *testing.T) {
			setup := bundledSetupFixture(t)
			_, ex := enableSELinux(setup)
			if failure == "conflict" {
				ex.Results["semanage port -l"] = FakeExecResult{Stdout: "ssh_port_t tcp 4000-5000\n"}
			} else {
				ex.Results["semanage port -a"] = FakeExecResult{ExitCode: 1}
			}
			r := &SetPortRunner{FS: setup.FS, Paths: setup.Paths, Exec: ex, Env: setup.Env, Systemd: setup.Systemd, Out: setup.Out}
			err := r.Run("4567")
			require.Error(t, err)
			require.Equal(t, "3210", setup.Env.(*FakeEnvManager).Env["PORT"])
			require.Empty(t, setup.Systemd.(*FakeSystemdRunner).Actions)
		})
	}
}

type labelOrderSystemd struct {
	*FakeSystemdRunner
	exec *FakeExecRunner
	fs   *FakeFileSystem
	t    *testing.T
}

func (s *labelOrderSystemd) Start(unit string) error {
	s.check(unit)
	return s.FakeSystemdRunner.Start(unit)
}
func (s *labelOrderSystemd) Restart(unit string) error {
	s.check(unit)
	return s.FakeSystemdRunner.Restart(unit)
}
func (s *labelOrderSystemd) check(unit string) {
	var paths []string
	switch unit {
	case bundledPGService:
		paths = []string{bundledPGSocket, bundledPGData}
	case bundledCaddyService:
		paths = []string{"/run/heimdall-caddy", DefaultPaths().ConfigDir + "/caddy"}
	case ServiceName:
		paths = []string{DefaultPaths().ConfigDir}
		require.False(s.t, s.fs.Exists(DefaultPaths().ConfigDir+"/upgrade-pending"))
	}
	for _, p := range paths {
		found := false
		for _, c := range s.exec.Calls {
			if c.Name == "restorecon" {
				for _, a := range c.Args {
					if a == p || strings.HasPrefix(p, a+"/") {
						found = true
					}
				}
			}
		}
		require.True(s.t, found, "%s must be relabeled before %s starts", p, unit)
	}
}
func TestBundledSELinuxLabelsBeforePrivateServicesStart(t *testing.T) {
	r := bundledSetupFixture(t)
	fs, ex := enableSELinux(r)
	for _, dir := range []string{r.Paths.AppDir, r.Paths.LibExecDir + "/runtime", r.Paths.LibExecDir + "/runtime/postgresql", r.Paths.LibExecDir + "/runtime/caddy", "/var/lib/heimdall-postgresql", bundledPGData, "/var/lib/heimdall-caddy"} {
		fs.Dirs[dir] = true
	}
	fs.Files[r.Paths.ConfigDir+"/upgrade-pending"] = nil
	r.Systemd = &labelOrderSystemd{r.Systemd.(*FakeSystemdRunner), ex, fs, t}
	require.NoError(t, r.Run())
}
func TestBundledSELinuxRelabelFailureBlocksActivation(t *testing.T) {
	r := bundledSetupFixture(t)
	_, ex := enableSELinux(r)
	ex.Results["restorecon -R"] = FakeExecResult{ExitCode: 1}
	require.Error(t, r.Run())
	require.Empty(t, r.Systemd.(*FakeSystemdRunner).Actions)
}
func TestFindTrustFilesPropagatesTraversalFailure(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/regular"
	require.NoError(t, os.WriteFile(file, nil, 0600))
	_, err := (&osFileSystem{}).FindFiles(file+"/child", "*.node")
	require.Error(t, err, "ENOTDIR is an error, not an empty trust inventory")
}

func TestSELinuxNativeGenericPortRanges(t *testing.T) {
	output := "SELinux Port Type              Proto    Port Number\nreserved_port_t tcp 0-511\nhttp_port_t tcp 80, 443, 488, 8008, 8009, 8443, 9000\nunreserved_port_t tcp 1024-32767, 61001-65535\nephemeral_port_t tcp 32768-61000\n"
	compatible, err := selinuxPortCompatible(output, selinuxPort{"postgresql_port_t", "55432"})
	require.NoError(t, err)
	require.False(t, compatible)
	compatible, err = selinuxPortCompatible(output, selinuxPort{"http_port_t", "443"})
	require.NoError(t, err)
	require.True(t, compatible)
}

func TestBundledUpgradeRejectsUnsafeMarker(t *testing.T) {
	for _, mode := range []os.FileMode{os.ModeSymlink | 0600, 0666} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			r := bundledSetupFixture(t)
			fs := r.FS.(*FakeFileSystem)
			path := r.Paths.ConfigDir + "/upgrade-pending"
			fs.Files[path] = nil
			r.FS = &securityFS{FakeFileSystem: fs, badPath: path, badMode: mode}
			before, _ := r.Env.ReadEnv()
			require.Error(t, r.Run())
			require.Equal(t, before, r.Env.(*FakeEnvManager).Env)
			require.Empty(t, r.Systemd.(*FakeSystemdRunner).Actions)
			require.True(t, fs.Exists(path))
		})
	}
}
func TestSELinuxLedgerRejectsNonnumericPort(t *testing.T) {
	require.False(t, validSELinuxPort(selinuxPort{"http_port_t", "+443"}))
}

type trustOrderExec struct {
	*FakeExecRunner
	t    *testing.T
	psql string
}

func (e *trustOrderExec) RunWithEnv(env map[string]string, name string, args ...string) (string, int, error) {
	if name == e.psql {
		trusted := false
		for _, c := range e.Calls {
			if c.Name == "fapolicyd-cli" && contains(c.Args, e.psql) {
				trusted = true
			}
		}
		require.True(e.t, trusted, "trust must precede the external-database private client preflight")
	}
	return e.FakeExecRunner.RunWithEnv(env, name, args...)
}
func TestBundledExternalPreflightTrustsPrivateClientFirst(t *testing.T) {
	r := bundledSetupFixture(t)
	r.DatabaseMode = "external"
	r.DBHost = "db.example.test"
	r.DBPort = 5432
	r.flagChanged = map[string]bool{"db-host": true, "db-port": true}
	r.Exec = &trustOrderExec{r.Exec.(*FakeExecRunner), t, r.Paths.RuntimePath("postgresql", "bin", "psql")}
	require.NoError(t, r.Run())
}
