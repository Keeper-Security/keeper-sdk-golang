package auth

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_auth"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"net/url"
	"strings"
)

var (
	_ IDeviceApprovalStep   = &deviceApprovalStep{}
	_ ISsoLoginInfo         = &ssoLoginInfo{}
	_ IAuthContext          = &authContext{}
	_ IConnectedStep        = &connectedStep{}
	_ ISsoTokenStep         = &ssoTokenStep{}
	_ ITwoFactorStep        = &twoFactorStep{}
	_ ITwoFactorChannelInfo = &twoFactorChannelInfo{}
	_ IPasswordStep         = &passwordStep{}
	_ ISsoDataKeyStep       = &ssoDataKeyShareStep{}
)

type genericAuthStep struct {
	loginState LoginState
	OnClose    func() error
}

func (gs *genericAuthStep) Close() (err error) {
	if gs.OnClose != nil {
		err = gs.OnClose()
	}
	return
}
func (gs *genericAuthStep) LoginState() LoginState {
	return gs.loginState
}

type deviceApprovalStep struct {
	genericAuthStep
	onSendPush func(DeviceApprovalChannel) error
	onSendCode func(DeviceApprovalChannel, string) error
	onResume   func() error
}

func (das *deviceApprovalStep) SendPush(channel DeviceApprovalChannel) error {
	return das.onSendPush(channel)
}
func (das *deviceApprovalStep) SendCode(channel DeviceApprovalChannel, code string) error {
	return das.onSendCode(channel, code)
}
func (das *deviceApprovalStep) Resume() error {
	return das.onResume()
}

type passwordStep struct {
	genericAuthStep
	username             string
	onVerifyPassword     func(string) error
	onVerifyBiometricKey func([]byte) error
}

func (ps *passwordStep) Username() string {
	return ps.username
}
func (ps *passwordStep) VerifyPassword(password string) error {
	if ps.onVerifyPassword != nil {
		return ps.onVerifyPassword(password)
	} else {
		return api.NewKeeperError("Password Step: Verify password is not implemented")
	}
}
func (ps *passwordStep) VerifyBiometricKey(key []byte) error {
	if ps.onVerifyBiometricKey != nil {
		return ps.onVerifyBiometricKey(key)
	} else {
		return api.NewKeeperError("Password Step: Verify biometric key is not implemented")
	}
}

type twoFactorChannelInfo struct {
	channelType TwoFactorChannel
	channelName string
	channelUid  []byte
	phone       string
	pushActions []TwoFactorPushAction
	challenge   string
	maxDuration TwoFactorDuration
}

func (tci *twoFactorChannelInfo) MaxDuration() TwoFactorDuration {
	return tci.maxDuration
}
func (tci *twoFactorChannelInfo) ChannelType() TwoFactorChannel {
	return tci.channelType
}
func (tci *twoFactorChannelInfo) ChannelName() string {
	return tci.channelName
}
func (tci *twoFactorChannelInfo) ChannelUid() []byte {
	return tci.channelUid
}
func (tci *twoFactorChannelInfo) Phone() string {
	return tci.phone
}
func (tci *twoFactorChannelInfo) PushActions() []TwoFactorPushAction {
	return tci.pushActions[:]
}

type twoFactorStep struct {
	genericAuthStep
	duration   TwoFactorDuration
	channels   []ITwoFactorChannelInfo
	onSendPush func([]byte, TwoFactorPushAction) error
	onSendCode func([]byte, string) error
	onResume   func() error
}

func (tf *twoFactorStep) Duration() TwoFactorDuration {
	return tf.duration
}
func (tf *twoFactorStep) SetDuration(duration TwoFactorDuration) {
	tf.duration = duration
}
func (tf *twoFactorStep) Channels() []ITwoFactorChannelInfo {
	return tf.channels[:]
}
func (tf *twoFactorStep) SendPush(channelUid []byte, action TwoFactorPushAction) error {
	if tf.onSendPush != nil {
		return tf.onSendPush(channelUid, action)
	}
	return api.NewKeeperError("2FA Send Push not configured")
}
func (tf *twoFactorStep) SendCode(channelUid []byte, code string) error {
	if tf.onSendCode != nil {
		return tf.onSendCode(channelUid, code)
	}
	return api.NewKeeperError("2FA Send Push not configured")
}
func (tf *twoFactorStep) Resume() error {
	if tf.onResume != nil {
		return tf.onResume()
	}
	return api.NewKeeperError("2FA Send Push not configured")
}

func newReadyStep() ILoginStep {
	return &genericAuthStep{
		loginState: LoginState_Ready,
	}
}

type errorStep struct {
	genericAuthStep
	err error
}

func (es *errorStep) Error() error {
	return es.err
}
func newErrorStep(err error) IErrorStep {
	return &errorStep{
		genericAuthStep: genericAuthStep{
			loginState: LoginState_Error,
		},
		err: err,
	}
}

type connectedStep struct {
	genericAuthStep
	keeperAuth *keeperAuth
}

func (cs *connectedStep) TakeKeeperAuth() (result IKeeperAuth, err error) {
	if cs.keeperAuth != nil {
		result = cs.keeperAuth
	} else {
		err = api.NewKeeperError("Keeper Authentication is already taken")
	}
	return
}

type ssoDataKeyShareStep struct {
	genericAuthStep
	onRequestDataKey func(DataKeyShareChannel) error
	onResume         func() error
}

func (dkss *ssoDataKeyShareStep) Channels() []DataKeyShareChannel {
	return []DataKeyShareChannel{
		DataKeyShare_KeeperPush,
		DataKeyShare_AdminApproval,
	}
}
func (dkss *ssoDataKeyShareStep) RequestDataKey(channel DataKeyShareChannel) error {
	if dkss.onRequestDataKey != nil {
		return dkss.onRequestDataKey(channel)
	} else {
		return api.NewKeeperError("SSO Daka Key Share Step: RequestDataKey is not implemented")
	}
}
func (dkss *ssoDataKeyShareStep) Resume() error {
	if dkss.onResume != nil {
		return dkss.onResume()
	} else {
		return api.NewKeeperError("SSO Daka Key Share Step: Resume is not implemented")
	}
}

type ssoTokenStep struct {
	genericAuthStep
	isCloudSso          bool
	loginName           string
	loginAsProvider     bool
	ssoLoginUrl         string
	onSetSsoToken       func(string) error
	onLoginWithPassword func() error
}

func (sst *ssoTokenStep) LoginWithPassword() error {
	if sst.onLoginWithPassword != nil {
		return sst.onLoginWithPassword()
	}
	return api.NewKeeperError("SSO Token Step: Master Password is not implemented")
}

func (sst *ssoTokenStep) LoginName() string {
	return sst.loginName
}
func (sst *ssoTokenStep) LoginAsProvider() bool {
	return sst.loginAsProvider
}
func (sst *ssoTokenStep) SsoLoginUrl() string {
	return sst.ssoLoginUrl
}
func (sst *ssoTokenStep) IsCloudSso() bool {
	return sst.isCloudSso
}
func (sst *ssoTokenStep) SetSsoToken(token string) error {
	if sst.onSetSsoToken != nil {
		return sst.onSetSsoToken(token)
	}
	return api.NewKeeperError("Set SSOToken step is not configured")
}

func (la *loginAuth) onRequiresAuthHash(response *proto_auth.LoginResponse) (err error) {
	if len(response.Salt) == 0 {
		err = api.NewKeeperApiError(
			"account-recovery-required",
			"Your account requires account recovery in order to use a Master Password authentication method.\n\n"+
				"Account recovery (Forgot Password) is available in the Web Vault or Enterprise Console.")
		return
	}
	var salt = response.Salt[0]
	var saltName = "master"
	if la.alternatePassword {
		saltName = "alternate"
	}
	for _, x := range response.Salt {
		var name = strings.ToLower(x.Name)
		if name == saltName {
			salt = x
			break
		}
	}

	var ps = &passwordStep{
		genericAuthStep: genericAuthStep{
			loginState: LoginState_Password,
		},
		username: la.loginContext.Username,
		onVerifyPassword: func(password string) (er1 error) {
			var rq = &proto_auth.ValidateAuthHashRequest{
				PasswordMethod:      proto_auth.PasswordMethod_ENTERED,
				AuthResponse:        api.DeriveKeyHashV1(password, salt.Salt, uint32(salt.Iterations)),
				EncryptedLoginToken: response.EncryptedLoginToken,
			}
			var rs = new(proto_auth.LoginResponse)
			er1 = la.executeRest("authentication/validate_auth_hash", rq, rs, nil)
			if er1 == nil {
				er1 = la.onLoggedIn(rs, func(encryptedDataKey []byte) ([]byte, error) {
					var encryptionKey = api.DeriveKeyHashV2("data_key", password, salt.GetSalt(), uint32(salt.GetIterations()))
					return api.DecryptAesV2(encryptedDataKey, encryptionKey)
				})
				if er1 == nil {
					api.GetLogger().Info("Successfully authenticated with Master Password")
				}
			}
			return
		},
		onVerifyBiometricKey: nil,
	}

	la.setLoginStep(ps)
	return nil
}

func (la *loginAuth) onRequires2fa(response *proto_auth.LoginResponse) error {
	var lastPushChannelUid []byte

	var tfs = &twoFactorStep{
		genericAuthStep: genericAuthStep{
			loginState: LoginState_TwoFactor,
		},
		duration: TwoFactorDuration_EveryLogin,
	}
	for _, ch := range response.Channels {
		var ti = &twoFactorChannelInfo{
			channelType: protoTfaChannelToSdk(ch.GetChannelType()),
			channelName: ch.GetChannelName(),
			channelUid:  ch.GetChannelUid(),
			phone:       ch.GetPhoneNumber(),
			challenge:   ch.GetChallenge(),
			maxDuration: protoTfaDurationToSdk(ch.MaxExpiration),
		}
		switch ti.channelType {
		case TwoFactorChannel_TextMessage:
			ti.pushActions = []TwoFactorPushAction{TwoFactorAction_TextMessage}
		case TwoFactorChannel_KeeperDNA:
			ti.pushActions = []TwoFactorPushAction{TwoFactorAction_KeeperDna}
		case TwoFactorChannel_DuoSecurity:
			for _, x := range ch.GetCapabilities() {
				switch x {
				case "push":
					ti.pushActions = append(ti.pushActions, TwoFactorAction_DuoPush)
				case "sms":
					ti.pushActions = append(ti.pushActions, TwoFactorAction_DuoTextMessage)
				case "phone":
					ti.pushActions = append(ti.pushActions, TwoFactorAction_DuoVoiceCall)
				}
			}
		}
		tfs.channels = append(tfs.channels, ti)
	}
	tfs.onSendPush = func(channelUid []byte, action TwoFactorPushAction) (er1 error) {
		var rq = &proto_auth.TwoFactorSendPushRequest{
			PushType:            sdkActionToProto(action),
			EncryptedLoginToken: response.EncryptedLoginToken,
			ChannelUid:          channelUid,
		}
		er1 = la.executeRest("authentication/2fa_send_push", rq, nil, nil)
		if er1 == nil {
			lastPushChannelUid = channelUid
		}
		return
	}
	tfs.onSendCode = func(channelUid []byte, code string) (er1 error) {
		var valueType = proto_auth.TwoFactorValueType_TWO_FA_CODE_NONE
		for _, ch := range tfs.channels {
			if bytes.Equal(ch.ChannelUid(), channelUid) {
				valueType = sdkTfaChannelToProtoTfaValue(ch.ChannelType())
				break
			}
		}
		var rq = &proto_auth.TwoFactorValidateRequest{
			EncryptedLoginToken: response.EncryptedLoginToken,
			ValueType:           valueType,
			Value:               code,
			ChannelUid:          channelUid,
			ExpireIn:            sdkTfaDurationToProto(tfs.duration),
		}
		var rs = new(proto_auth.TwoFactorValidateResponse)
		er1 = la.executeRest("authentication/2fa_validate", rq, rs, nil)
		if er1 == nil {
			er1 = la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, response.EncryptedLoginToken)
		}
		return
	}
	tfs.onResume = func() error {
		return la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, response.EncryptedLoginToken)
	}
	tfs.OnClose = func() error {
		if la.pushNotifications != nil {
			la.pushNotifications.RemoveAllCallback()
		}
		return nil
	}

	var handler = func(event *NotificationEvent) bool {
		if event.Event == "received_totp" {
			var er1 error
			if len(event.EncryptedLoginToken) > 0 {
				er1 = la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, api.Base64UrlDecode(event.EncryptedLoginToken))
				if er1 != nil {
					api.GetLogger().Warn("2FA Push Notification", zap.Error(er1))
				}
			} else if len(event.Passcode) > 0 {
				if lastPushChannelUid != nil {
					_ = tfs.onSendCode(lastPushChannelUid, event.Passcode)
				}
			}
		}
		return false
	}
	la.ensurePushNotifications()
	if la.pushNotifications != nil {
		la.pushNotifications.RegisterCallback(handler)
	}
	la.setLoginStep(tfs)
	return nil
}

func (la *loginAuth) onDeviceApprovalRequired(response *proto_auth.LoginResponse) (err error) {
	la.ensurePushNotifications()
	var handler = func(event *NotificationEvent) bool {
		var token []byte
		if event.Event == "received_totp" {
			token = response.EncryptedLoginToken
			if len(event.EncryptedLoginToken) > 0 {
				token = api.Base64UrlDecode(event.EncryptedLoginToken)
			}
		} else if event.Message == "device_approved" {
			if event.Approved {
				token = response.EncryptedLoginToken
			}
		} else if event.Command == "device_verified" {
			token = response.EncryptedLoginToken
		}
		if token != nil {
			var er1 error
			if er1 = la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, token); er1 != nil {
				api.GetLogger().Warn("Device Approval Error", zap.Error(er1))
			}
		}
		return false
	}
	var emailSent = false
	var das = &deviceApprovalStep{
		genericAuthStep: genericAuthStep{
			loginState: LoginState_DeviceApproval,
			OnClose: func() error {
				if la.pushNotifications != nil {
					la.pushNotifications.RemoveAllCallback()
				}
				return nil
			},
		},
		onSendPush: func(channel DeviceApprovalChannel) (er1 error) {
			if channel == DeviceApproval_Email {
				var rqEmail = &proto_auth.DeviceVerificationRequest{
					Username:             la.loginContext.Username,
					EncryptedDeviceToken: la.loginContext.DeviceToken,
					MessageSessionUid:    la.loginContext.MessageSessionUid,
					ClientVersion:        la.endpoint.ClientVersion(),
				}
				if emailSent {
					rqEmail.VerificationChannel = "email_resend"
				} else {
					rqEmail.VerificationChannel = "email"
				}
				er1 = la.executeRest("authentication/request_device_verification", rqEmail, nil, nil)
			} else {
				var rqPush = &proto_auth.TwoFactorSendPushRequest{
					EncryptedLoginToken: response.EncryptedLoginToken,
				}
				if channel == DeviceApproval_KeeperPush {
					rqPush.PushType = proto_auth.TwoFactorPushType_TWO_FA_PUSH_KEEPER
				} else {
					rqPush.PushType = proto_auth.TwoFactorPushType_TWO_FA_PUSH_NONE
				}
				er1 = la.executeRest("authentication/2fa_send_push", rqPush, nil, nil)
			}
			return
		},
		onSendCode: func(channel DeviceApprovalChannel, code string) (er1 error) {
			var token = response.EncryptedLoginToken
			if channel == DeviceApproval_Email {
				var rqEmail = &proto_auth.ValidateDeviceVerificationCodeRequest{
					Username:             la.loginContext.Username,
					ClientVersion:        la.endpoint.ClientVersion(),
					VerificationCode:     code,
					MessageSessionUid:    la.loginContext.MessageSessionUid,
					EncryptedDeviceToken: la.loginContext.DeviceToken,
				}
				er1 = la.executeRest("authentication/validate_device_verification_code", rqEmail, nil, nil)
			} else if channel == DeviceApproval_TwoFactorAuth {
				var rq2fa = &proto_auth.TwoFactorValidateRequest{
					EncryptedLoginToken: response.EncryptedLoginToken,
					ValueType:           proto_auth.TwoFactorValueType_TWO_FA_CODE_NONE,
					Value:               code,
				}
				var rs2fa = new(proto_auth.TwoFactorValidateResponse)
				er1 = la.executeRest("authentication/2fa_validate", rq2fa, rs2fa, nil)
				if er1 == nil {
					if len(rs2fa.EncryptedLoginToken) > 0 {
						token = rs2fa.EncryptedLoginToken
					}
				}
			}
			if er1 == nil {
				er1 = la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, token)
			}
			return
		},
		onResume: func() error {
			return la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, response.EncryptedLoginToken)
		},
	}
	if la.pushNotifications != nil {
		la.pushNotifications.RegisterCallback(handler)
	}
	la.setLoginStep(das)
	return
}

func (la *loginAuth) onRequestDataKey(loginToken []byte) (err error) {
	la.ensurePushNotifications()
	var dkss = &ssoDataKeyShareStep{
		genericAuthStep: genericAuthStep{
			loginState: LoginState_SsoDataKey,
			OnClose: func() error {
				if la.pushNotifications != nil {
					la.pushNotifications.RemoveAllCallback()
				}
				return nil
			},
		},
		onRequestDataKey: func(channel DataKeyShareChannel) (er1 error) {
			switch channel {
			case DataKeyShare_KeeperPush:
				var rqPush = &proto_auth.TwoFactorSendPushRequest{
					EncryptedLoginToken: loginToken,
					PushType:            proto_auth.TwoFactorPushType_TWO_FA_PUSH_KEEPER,
				}
				er1 = la.executeRest("authentication/2fa_send_push", rqPush, nil, nil)
			case DataKeyShare_AdminApproval:
				var rqAdmin = &proto_auth.DeviceVerificationRequest{
					Username:             la.loginContext.Username,
					EncryptedDeviceToken: la.loginContext.DeviceToken,
					MessageSessionUid:    la.loginContext.MessageSessionUid,
					ClientVersion:        la.endpoint.ClientVersion(),
				}
				var rsAdmin = new(proto_auth.DeviceVerificationResponse)
				if er1 = la.executeRest("authentication/2fa_send_push", rqAdmin, rsAdmin, nil); er1 == nil {
					if rsAdmin.GetDeviceStatus() == proto_auth.DeviceStatus_DEVICE_OK {
						er1 = la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, loginToken)
					}
				}
			}
			return
		},
		onResume: func() error {
			return la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, loginToken)
		},
	}
	var handle = func(event *NotificationEvent) bool {
		var token []byte
		if event.Message == "device_approved" {
			if event.Approved {
				token = loginToken
			}
		} else if event.Command == "device_verified" {
			token = loginToken
		}
		if token != nil {
			_ = la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, loginToken)
		}
		return false
	}
	if la.pushNotifications != nil {
		la.pushNotifications.RegisterCallback(handle)
	}
	la.setLoginStep(dkss)
	return nil
}

func (la *loginAuth) onSsoRedirect(loginToken []byte) (err error) {
	var logger = api.GetLogger()
	var ssoInfo = la.loginContext.SsoLoginInfo
	var sts = &ssoTokenStep{
		genericAuthStep: genericAuthStep{
			loginState: LoginState_SsoToken,
		},
		isCloudSso: ssoInfo.IsCloud(),
	}
	if ssoInfo.SsoProvider() != "" {
		sts.loginName = ssoInfo.SsoProvider()
		sts.loginAsProvider = true
	} else {
		sts.loginName = la.loginContext.Username
		sts.loginAsProvider = false
	}
	var uri *url.URL
	var data []byte
	var lt = loginToken
	if uri, err = url.Parse(ssoInfo.SsoUrl()); err == nil {
		if sts.IsCloudSso() {
			var transmissionKey = api.GenerateAesKey()
			var rq = &proto_auth.SsoCloudRequest{
				MessageSessionUid: la.loginContext.MessageSessionUid,
				ClientVersion:     la.endpoint.ClientVersion(),
				Embedded:          true,
				ForceLogin:        false,
			}

			if data, err = proto.Marshal(rq); err == nil {
				var apiRq *proto_auth.ApiRequest
				var keyId = la.endpoint.ServerKeyId()
				var locale = la.endpoint.Locale()
				if apiRq, err = PrepareApiRequest(keyId, data, transmissionKey, nil, locale); err == nil {
					if data, err = proto.Marshal(apiRq); err == nil {
						var q = uri.Query()
						q.Add("payload", api.Base64UrlEncode(data))
						uri.RawQuery = q.Encode()
						sts.ssoLoginUrl = uri.String()
						sts.onSetSsoToken = func(token string) (er1 error) {
							if data, er1 = api.DecryptAesV2(api.Base64UrlDecode(token), transmissionKey); er1 == nil {
								var tokenRs = new(proto_auth.SsoCloudResponse)
								if er1 = proto.Unmarshal(data, tokenRs); er1 != nil {
									la.loginContext.Username = tokenRs.Email
									ssoInfo.ssoProvider = tokenRs.ProviderName
									ssoInfo.idpSessionId = tokenRs.IdpSessionId
									if len(tokenRs.EncryptedLoginToken) > 0 {
										lt = tokenRs.EncryptedLoginToken
									}
									if lt == nil {
										er1 = la.startLogin(proto_auth.LoginMethod_AFTER_SSO, false)
									} else {
										er1 = la.resumeLogin(proto_auth.LoginMethod_AFTER_SSO, lt)
									}
								}
							}
							return
						}
						sts.onLoginWithPassword = func() error {
							la.alternatePassword = true
							la.loginContext.AccountType = AuthType_Regular
							return la.startLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, true)
						}
					}
				}
			}
		} else {
			var rsaPrivate *rsa.PrivateKey
			var rsaPublic *rsa.PublicKey
			if rsaPrivate, rsaPublic, err = api.GenerateRsaKey(); err == nil {
				var q = uri.Query()
				q.Add("key", api.Base64UrlEncode(api.UnloadRsaPublicKey(rsaPublic)))
				q.Add("embedded", "")
				uri.RawQuery = q.Encode()
				sts.ssoLoginUrl = uri.String()
				sts.onSetSsoToken = func(token string) (er1 error) {
					var st = new(database.SsoToken)
					if er1 = json.Unmarshal([]byte(token), &st); er1 == nil {
						la.loginContext.Username = st.Email
						ssoInfo.ssoProvider = st.ProviderName
						ssoInfo.idpSessionId = st.SessionId
						if len(st.Password) > 0 {
							if data, er1 = api.DecryptRsa(api.Base64UrlDecode(st.Password), rsaPrivate); er1 == nil {
								la.loginContext.Passwords = append(la.loginContext.Passwords, string(data))
							} else {
								logger.Warn("Onsite SSO decrypt password error", zap.Error(er1))
							}
						}
						if len(st.NewPassword) > 0 {
							if data, er1 = api.DecryptRsa(api.Base64UrlDecode(st.NewPassword), rsaPrivate); er1 == nil {
								la.loginContext.Passwords = append(la.loginContext.Passwords, string(data))
							} else {
								logger.Warn("Onsite SSO decrypt password error", zap.Error(er1))
							}
						}
						if len(st.LoginToken) > 0 {
							lt = api.Base64UrlDecode(st.LoginToken)
						}
						if lt == nil {
							er1 = la.startLogin(proto_auth.LoginMethod_AFTER_SSO, false)
						} else {
							er1 = la.resumeLogin(proto_auth.LoginMethod_AFTER_SSO, lt)
						}
					}
					return
				}
			}
		}
	}

	return
}

func (la *loginAuth) onLoggedIn(response *proto_auth.LoginResponse, decryptor func([]byte) ([]byte, error)) (err error) {
	var logger = api.GetLogger()

	la.loginContext.Username = response.PrimaryUsername
	la.loginContext.CloneCode = response.CloneCode
	if err = la.storeConfiguration(); err != nil {
		logger.Warn("Save configuration error", zap.Error(err))
		return
	}

	var dataKey []byte
	if dataKey, err = decryptor(response.EncryptedDataKey); err != nil {
		logger.Warn("Decrypt data key error", zap.Error(err))
		return
	}

	var ac = &authContext{
		username:           la.loginContext.Username,
		accountUid:         api.Base64UrlEncode(response.AccountUid),
		sessionToken:       response.EncryptedSessionToken,
		sessionRestriction: getSessionTokenScope(response.SessionTokenType),
		dataKey:            dataKey,
		ssoLoginInfo:       la.loginContext.SsoLoginInfo,
		deviceToken:        la.loginContext.DeviceToken,
		devicePrivateKey:   la.loginContext.DevicePrivateKey,
	}

	if err = la.postLogin(ac); err != nil {
		return
	}
	if ac.SessionRestriction() == SessionRestriction_Unrestricted {
		la.ensurePushNotifications()
		_ = la.pushNotifications.SendToPushChannel(ac.SessionToken(), false)
	}

	var cs = &connectedStep{
		genericAuthStep: genericAuthStep{
			loginState: LoginState_Connected,
		},
		keeperAuth: &keeperAuth{
			endpoint:          la.endpoint,
			authContext:       ac,
			pushNotifications: la.pushNotifications,
			ttk:               newTimeToKeepalive(ac),
		},
	}
	la.pushNotifications = nil
	cs.OnClose = func() error {
		var ka IKeeperAuth
		var kerr error
		if ka, kerr = cs.TakeKeeperAuth(); kerr == nil {
			_ = ka.Close()
		}
		return nil
	}
	la.setLoginStep(cs)
	return
}
