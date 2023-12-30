package auth

import (
	"crypto/ecdh"
	"crypto/rsa"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_account_summary"
	"google.golang.org/protobuf/proto"
	"io"
)

type SessionRestriction int32

const (
	SessionRestriction_Unrestricted    SessionRestriction = 0
	SessionRestriction_AccountRecovery                    = 1 << 0
	SessionRestriction_ShareAccount                       = 1 << 1
	SessionRestriction_AcceptInvite                       = 1 << 2
	SessionRestriction_AccountExpired                     = 1 << 3
)

func (r SessionRestriction) Has(restriction SessionRestriction) bool {
	return r&restriction != 0
}

type IAuthContext interface {
	Username() string
	AccountUid() string
	SessionToken() []byte
	SessionRestriction() SessionRestriction
	DataKey() []byte
	ClientKey() []byte
	RsaPrivateKey() *rsa.PrivateKey
	EcPrivateKey() *ecdh.PrivateKey
	EcPublicKey() *ecdh.PublicKey
	EnterpriseEcPublicKey() *ecdh.PublicKey
	EnterpriseRsaPublicKey() *rsa.PublicKey
	IsEnterpriseAdmin() bool
	License() *proto_account_summary.License
	Settings() *proto_account_summary.Settings
	Enforcements() *proto_account_summary.Enforcements
	SsoLoginInfo() ISsoLoginInfo
	DeviceToken() []byte
	DevicePrivateKey() *ecdh.PrivateKey
}

type IKeeperAuth interface {
	io.Closer
	Endpoint() IKeeperEndpoint
	PushNotifications() IPushEndpoint
	AuthContext() IAuthContext
	ExecuteAuthCommand(api.IKeeperCommand, api.IKeeperResponse, bool) error
	ExecuteAuthRest(string, proto.Message, proto.Message) error
	ExecuteBatch([]api.IKeeperCommand) ([]*api.KeeperApiResponse, error)
	OnIdle()
}
