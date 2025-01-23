package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type Config struct {
	DiscoverWorkloadPath bool  `hcl:"discover_workload_path"`
	WorkloadSizeLimit    int64 `hcl:"workload_size_limit"`
}

type processInfo interface {
	Uids() ([]uint32, error)
	Gids() ([]uint32, error)
	Groups() ([]string, error)
	Exe() (string, error)
	NamespacedExe() string
}

type PSProcessInfo struct {
	*process.Process
}

func (ps PSProcessInfo) NamespacedExe() string {
	return getProcPath(ps.Pid, "exe")
}

// Groups returns the supplementary group IDs.
// This implementation currently only supports Linux.
func (ps PSProcessInfo) Groups() ([]string, error) {
	if runtime.GOOS != "linux" {
		return []string{}, nil
	}

	statusPath := getProcPath(ps.Pid, "status")
	return parseProcStatusGroups(statusPath)
}

func parseProcStatusGroups(statusPath string) ([]string, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scnr := bufio.NewScanner(f)
	for scnr.Scan() {
		row := scnr.Text()
		parts := strings.SplitN(row, ":", 2)
		if len(parts) != 2 {
			continue
		}

		if strings.ToLower(strings.TrimSpace(parts[0])) == "groups" {
			return strings.Fields(strings.TrimSpace(parts[1])), nil
		}
	}

	return nil, scnr.Err()
}

type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
	configv1.UnimplementedConfigServer
	configMtx sync.RWMutex
	config    *Config
	logger    hclog.Logger
	hooks     struct {
		newProcess      func(pid int32) (processInfo, error)
		lookupUserByID  func(id string) (*user.User, error)
		lookupGroupByID func(id string) (*user.Group, error)
	}
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		return nil, err
	}

	selectorValues, err := p.collectSelectorValues(req.Pid, config)
	if err != nil {
		return nil, err
	}

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectorValues,
	}, nil
}

func (p *Plugin) collectSelectorValues(pid int32, config *Config) ([]string, error) {
	proc, err := p.hooks.newProcess(pid)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get process: %v", err)
	}

	var selectorValues []string
	selectorValues = append(selectorValues, "new:true")

	if uid, err := p.getUID(proc); err == nil {
		selectorValues = append(selectorValues, makeSelectorValue("uid", uid))
		if user, ok := p.getUserName(uid); ok {
			selectorValues = append(selectorValues, makeSelectorValue("user", user))
		}
	}

	if gid, err := p.getGID(proc); err == nil {
		selectorValues = append(selectorValues, makeSelectorValue("gid", gid))
		if group, ok := p.getGroupName(gid); ok {
			selectorValues = append(selectorValues, makeSelectorValue("group", group))
		}
	}

	if sgIDs, err := proc.Groups(); err == nil {
		for _, sgID := range sgIDs {
			selectorValues = append(selectorValues, makeSelectorValue("supplementary_gid", sgID))
			if sGroup, ok := p.getGroupName(sgID); ok {
				selectorValues = append(selectorValues, makeSelectorValue("supplementary_group", sGroup))
			}
		}
	}

	if config.DiscoverWorkloadPath {
		if pathValues, err := p.buildPathSelectors(proc, config); err == nil {
			selectorValues = append(selectorValues, pathValues...)
		}
	}

	return selectorValues, nil
}

func (p *Plugin) buildPathSelectors(proc processInfo, config *Config) ([]string, error) {
	processPath, err := p.getPath(proc)
	if err != nil {
		return nil, err
	}

	selectorValues := []string{makeSelectorValue("path", processPath)}

	if config.WorkloadSizeLimit >= 0 {
		nsPath, err := p.getNamespacedPath(proc)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}

		sha256Digest, err := GetSHA256Digest(nsPath, config.WorkloadSizeLimit)
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		selectorValues = append(selectorValues, makeSelectorValue("sha256", sha256Digest))
	}

	return selectorValues, nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := parseConfig(req.HclConfiguration)
	if err != nil {
		return nil, err
	}
	p.setConfig(config)
	p.initializeHooks()
	return &configv1.ConfigureResponse{}, nil
}

func parseConfig(hclConfig string) (*Config, error) {
	config := new(Config)
	if err := hcl.Decode(config, hclConfig); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}
	return config, nil
}

func (p *Plugin) initializeHooks() {
	p.hooks.newProcess = func(pid int32) (processInfo, error) {
		pr, err := process.NewProcess(pid)
		return PSProcessInfo{pr}, err
	}
	p.hooks.lookupUserByID = user.LookupId
	p.hooks.lookupGroupByID = user.LookupGroupId
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

func (p *Plugin) setConfig(config *Config) {
	p.configMtx.Lock()
	defer p.configMtx.Unlock()
	p.config = config
}

func (p *Plugin) getConfig() (*Config, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()
	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func main() {
	plugin := new(Plugin)
	pluginmain.Serve(
		workloadattestorv1.WorkloadAttestorPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}

func (p *Plugin) getUID(proc processInfo) (string, error) {
	uids, err := proc.Uids()
	if err != nil || len(uids) == 0 {
		return "", status.Errorf(codes.Internal, "UIDs lookup: %v", err)
	}
	if len(uids) == 1 {
		return fmt.Sprint(uids[0]), nil
	}
	return fmt.Sprint(uids[1]), nil
}

func (p *Plugin) getUserName(uid string) (string, bool) {
	u, err := p.hooks.lookupUserByID(uid)
	if err != nil {
		return "", false
	}
	return u.Username, true
}

func (p *Plugin) getGID(proc processInfo) (string, error) {
	gids, err := proc.Gids()
	if err != nil || len(gids) == 0 {
		return "", status.Errorf(codes.Internal, "GIDs lookup: %v", err)
	}
	if len(gids) == 1 {
		return fmt.Sprint(gids[0]), nil
	}
	return fmt.Sprint(gids[1]), nil
}

func (p *Plugin) getGroupName(gid string) (string, bool) {
	g, err := p.hooks.lookupGroupByID(gid)
	if err != nil {
		return "", false
	}
	return g.Name, true
}

func (p *Plugin) getPath(proc processInfo) (string, error) {
	path, err := proc.Exe()
	if err != nil {
		return "", status.Errorf(codes.Internal, "path lookup: %v", err)
	}
	return path, nil
}

func (p *Plugin) getNamespacedPath(proc processInfo) (string, error) {
	if runtime.GOOS == "linux" {
		return proc.NamespacedExe(), nil
	}
	return proc.Exe()
}

func makeSelectorValue(kind, value string) string {
	return fmt.Sprintf("%s:%s", kind, value)
}

func getProcPath(pID int32, lastPath string) string {
	procPath := os.Getenv("HOST_PROC")
	if procPath == "" {
		procPath = "/proc"
	}
	return filepath.Join(procPath, strconv.FormatInt(int64(pID), 10), lastPath)
}

func GetSHA256Digest(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("SHA256 digest: %w", err)
	}
	defer f.Close()

	if limit > 0 {
		if err := checkFileSize(f, limit); err != nil {
			return "", err
		}
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("SHA256 digest: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func checkFileSize(f *os.File, limit int64) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("SHA256 digest: %w", err)
	}
	if fi.Size() > limit {
		return fmt.Errorf("SHA256 digest: workload %s exceeds size limit (%d > %d)", f.Name(), fi.Size(), limit)
	}
	return nil
}
