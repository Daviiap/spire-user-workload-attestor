package presentation

import (
	"wl/plugin/domain"
)

type UserAttestorModule interface {
	GetUserAttestationData() (*domain.UserAttestation, error)
}
