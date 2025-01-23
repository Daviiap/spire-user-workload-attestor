package presentation

import "wl/plugin/domain"

type UserAuthService interface {
	ValidateData(data *domain.UserAttestation) (domain.UserAttestationValidation, error)
}
