package infrastructure

import (
	"context"
	"log"
	"time"
	"wl/plugin/domain"
	"wl/plugin/presentation"

	pb "wl/plugin/infrastructure/userAttestationModule/proto/user_attestor"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type UserAttestorModuleAdaptor struct {
	SocketPath string
	presentation.UserAttestorModule
}

func (adaptor UserAttestorModuleAdaptor) GetUserAttestationData() (*domain.UserAttestation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := grpc.NewClient(
		"unix://"+adaptor.SocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewAttestationServiceClient(conn)

	res, err := client.GetUserAttestation(ctx, &pb.Empty{})
	if err != nil {
		log.Fatalf("Could not get attestation: %v", err)
	}

	supplementaryGroups := make([]domain.GroupInfo, len(res.UserInfo.SystemInfo.SupplementaryGroups))
	for i, group := range res.UserInfo.SystemInfo.SupplementaryGroups {
		supplementaryGroups[i] = domain.GroupInfo{
			GroupID:   group.GroupId,
			GroupName: group.GroupName,
		}
	}

	return &domain.UserAttestation{
		Token: res.Token,
		UserInfo: domain.UserInfo{
			Name:   res.UserInfo.Name,
			Secret: res.UserInfo.Secret,
			SystemInfo: domain.SystemInfo{
				UserID:              res.UserInfo.SystemInfo.UserId,
				Username:            res.UserInfo.SystemInfo.Username,
				GroupID:             res.UserInfo.SystemInfo.GroupId,
				GroupName:           res.UserInfo.SystemInfo.GroupName,
				SupplementaryGroups: supplementaryGroups,
			},
		},
	}, nil
}
