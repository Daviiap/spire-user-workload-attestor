package plugin

import (
	"github.com/hashicorp/hcl"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Config struct {
	UserAttestationServiceURL       string `hcl:"user_attestation_service_url"`
	UserAttestationModuleSocketPath string `hcl:"user_attestation_module_path"`
}

func parseConfig(hclConfig string) (*Config, error) {
	config := new(Config)
	if err := hcl.Decode(config, hclConfig); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}
	return config, nil
}
