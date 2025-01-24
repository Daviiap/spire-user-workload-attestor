package infrastructure

import (
	"wl/plugin/domain"
	"wl/plugin/presentation"
)

type UserAuthServiceAdaptor struct {
	ServiceURL string
	presentation.UserAuthService
}

func (adaptor UserAuthServiceAdaptor) ValidateData(data *domain.UserAttestation) (domain.UserAttestationValidation, error) {
	return domain.UserAttestationValidation{IsValid: true, Message: "valid"}, nil
}
