package plugin

import (
	"context"
	"sync"
	"wl/plugin/domain"
	uamAdptr "wl/plugin/infrastructure/userAttestationModule"
	uasAdptr "wl/plugin/infrastructure/userAuthService"
	"wl/plugin/presentation"

	"github.com/hashicorp/go-hclog"
	"github.com/shirou/gopsutil/v4/process"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

type PSProcessInfo struct {
	*process.Process
}

type Plugin struct {
	workloadattestorv1.UnimplementedWorkloadAttestorServer
	configv1.UnimplementedConfigServer
	configMtx          sync.RWMutex
	config             *Config
	logger             hclog.Logger
	userAttestorModule presentation.UserAttestorModule
	userAuthService    presentation.UserAuthService
}

func (p *Plugin) Attest(ctx context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	config, err := p.getConfig()
	if err != nil {
		p.logger.Error("Failed to get the configuration", "error", err)
		return nil, err
	}

	p.SetUserAttestorModule(uamAdptr.UserAttestorModuleAdaptor{SocketPath: config.UserAttestationModuleSocketPath})
	p.SetUserAuthService(uasAdptr.UserAuthServiceAdaptor{ServiceURL: config.UserAttestationServiceURL})

	// 1. Communicate with user attestor module to get data
	attestationData, err := p.userAttestorModule.GetUserAttestationData()
	if err != nil {
		p.logger.Error("Failed to get attestation data", "error", err)
		return nil, err
	}
	// 2. Communicate with user auth service to validate token and data
	attestationResult, err := p.userAuthService.ValidateData(attestationData)
	if err != nil || !attestationResult.IsValid {
		p.logger.Error("Failed to validate data "+attestationResult.Message, "error", err)
		return nil, err
	}
	// 3. return selectors
	selectors, err := p.buildSelectors(&attestationData.UserInfo)
	if err != nil {
		p.logger.Error("Failed to build selectors", "error", err)
		return nil, err
	}

	return &workloadattestorv1.AttestResponse{
		SelectorValues: selectors,
	}, nil
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	if req.HclConfiguration == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration cannot be empty")
	}

	config, err := parseConfig(req.HclConfiguration)
	if err != nil {
		return nil, err
	}
	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// ======| private |======

func (p *Plugin) SetUserAttestorModule(userAttestorModule presentation.UserAttestorModule) {
	p.userAttestorModule = userAttestorModule
}

func (p *Plugin) SetUserAuthService(userAuthService presentation.UserAuthService) {
	p.userAuthService = userAuthService
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

func (p *Plugin) buildSelectors(userInfo *domain.UserInfo) ([]string, error) {
	selectors := []string{}

	selectors = append(selectors, "name:"+userInfo.Name)
	selectors = append(selectors, "secret:"+userInfo.Secret)
	selectors = append(selectors, "system:user_id:"+userInfo.SystemInfo.UserID)
	selectors = append(selectors, "system:username:"+userInfo.SystemInfo.Username)
	selectors = append(selectors, "system:group_id:"+userInfo.SystemInfo.GroupID)
	selectors = append(selectors, "system:groupName:"+userInfo.SystemInfo.GroupName)

	for _, group := range userInfo.SystemInfo.SupplementaryGroups {
		selectors = append(selectors, "system:supplementary_group_id:"+group.GroupID)
		selectors = append(selectors, "system:supplementary_group_name:"+group.GroupName)
	}

	return selectors, nil
}
