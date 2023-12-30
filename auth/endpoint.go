package auth

import (
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_auth"
)

type IKeeperEndpoint interface {
	ClientVersion() string
	SetClientVersion(string)
	DeviceName() string
	SetDeviceName(string)
	Locale() string
	SetLocale(string)
	Server() string
	SetServer(string)
	ServerKeyId() int32

	CommunicateKeeper(string, []byte, []byte) ([]byte, error)

	PushServer() string
	ConnectToPushServer(*proto_auth.WssConnectionRequest) (IPushEndpoint, error)
	ConfigurationStorage() IConfigurationStorage
}
