package auth

import (
	"io"
)

type LoginState = int

const (
	LoginState_Ready LoginState = iota + 1
	LoginState_DeviceApproval
	LoginState_TwoFactor
	LoginState_Password
	LoginState_SsoToken
	LoginState_SsoDataKey
	LoginState_Connected
	LoginState_Error
)

type ILoginStep interface {
	io.Closer
	LoginState() LoginState
}

type ILoginAuth interface {
	io.Closer
	Endpoint() IKeeperEndpoint
	Step() ILoginStep

	Login(string, ...string)
	LoginSso(string)

	AlternatePassword() bool
	SetAlternatePassword(bool)
	ResumeSession() bool
	SetResumeSession(bool)
	OnNextStep() func()
	SetOnNextStep(func())
	OnRegionChanged() func(string)
	SetOnRegionChanged(func(string))
}

type DeviceApprovalChannel = int32

const (
	DeviceApproval_Email DeviceApprovalChannel = iota
	DeviceApproval_TwoFactorAuth
	DeviceApproval_KeeperPush
)

type TwoFactorDuration = int32

const (
	TwoFactorDuration_EveryLogin TwoFactorDuration = iota
	TwoFactorDuration_Every12Hour
	TwoFactorDuration_EveryDay
	TwoFactorDuration_Every30Days
	TwoFactorDuration_Forever
)

type TwoFactorChannel = int32

const (
	TwoFactorChannel_Other TwoFactorChannel = iota
	TwoFactorChannel_Authenticator
	TwoFactorChannel_TextMessage
	TwoFactorChannel_DuoSecurity
	TwoFactorChannel_RSASecurID
	TwoFactorChannel_KeeperDNA
	TwoFactorChannel_SecurityKey
	TwoFactorChannel_Backup
)

type TwoFactorPushAction = int32

const (
	TwoFactorAction_DuoPush TwoFactorPushAction = iota + 1
	TwoFactorAction_DuoTextMessage
	TwoFactorAction_DuoVoiceCall
	TwoFactorAction_TextMessage
	TwoFactorAction_KeeperDna
)

type DataKeyShareChannel = int32

const (
	DataKeyShare_KeeperPush DataKeyShareChannel = iota + 1
	DataKeyShare_AdminApproval
)

type AccountAuthType int32

const (
	AuthType_Regular AccountAuthType = iota + 1
	AuthType_SsoCloud
	AuthType_OnsiteSso
	AuthType_ManagedCompany
)

type ITwoFactorChannelInfo interface {
	ChannelType() TwoFactorChannel
	ChannelName() string
	ChannelUid() []byte
	Phone() string
	PushActions() []TwoFactorPushAction
	MaxDuration() TwoFactorDuration
}

type ISsoLoginInfo interface {
	IsCloud() bool
	SsoProvider() string
	SsoUrl() string
	IdpSessionId() string
}

type IDeviceApprovalStep interface {
	ILoginStep
	SendPush(DeviceApprovalChannel) error
	SendCode(DeviceApprovalChannel, string) error
	Resume() error
}

type ITwoFactorStep interface {
	ILoginStep
	Channels() []ITwoFactorChannelInfo
	Duration() TwoFactorDuration
	SetDuration(TwoFactorDuration)
	SendPush([]byte, TwoFactorPushAction) error
	SendCode([]byte, string) error
	Resume() error
}

type IPasswordStep interface {
	ILoginStep
	Username() string
	VerifyPassword(string) error
	VerifyBiometricKey([]byte) error
}

type IConnectedStep interface {
	ILoginStep
	TakeKeeperAuth() (IKeeperAuth, error)
}

type IErrorStep interface {
	ILoginStep
	Error() error
}

type ISsoTokenStep interface {
	ILoginStep
	LoginName() string
	LoginAsProvider() bool
	SsoLoginUrl() string
	IsCloudSso() bool
	SetSsoToken(string) error
	LoginWithPassword() error
}

type ISsoDataKeyStep interface {
	ILoginStep
	Channels() []DataKeyShareChannel
	RequestDataKey(DataKeyShareChannel) error
	Resume() error
}
