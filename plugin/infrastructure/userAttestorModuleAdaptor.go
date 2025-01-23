package infrastructure

import (
	"wl/plugin/domain"
	"wl/plugin/presentation"
)

type UserAttestorModuleAdaptor struct {
	SocketPath string
	presentation.UserAttestorModule
}

func (adaptor UserAttestorModuleAdaptor) GetUserAttestationData() (*domain.UserAttestation, error) {
	return &domain.UserAttestation{}, nil
}
