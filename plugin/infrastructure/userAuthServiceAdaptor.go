package infrastructure

import (
	"wl/plugin/domain"
	"wl/plugin/presentation"
)

type UserAuthServiceAdaptor struct {
	ServiceURL string
	presentation.UserAuthService
}

func (adaptor UserAttestorModuleAdaptor) ValidateData(data *domain.UserAttestation) (domain.UserAttestationValidation, error) {
	return domain.UserAttestationValidation{}, nil
}
