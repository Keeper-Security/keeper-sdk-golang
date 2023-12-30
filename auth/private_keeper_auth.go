package auth

import (
	"crypto/ecdh"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/json_commands"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_account_summary"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"time"
)

var (
	_ IAuthContext = &authContext{}
	_ IKeeperAuth  = &keeperAuth{}
)

type authContext struct {
	username               string
	accountUid             string
	sessionToken           []byte
	sessionRestriction     SessionRestriction
	dataKey                []byte
	ssoLoginInfo           ISsoLoginInfo
	deviceToken            []byte
	devicePrivateKey       *ecdh.PrivateKey
	clientKey              []byte
	rsaPrivateKey          *rsa.PrivateKey
	ecPrivateKey           *ecdh.PrivateKey
	ecPublicKey            *ecdh.PublicKey
	enterpriseEcPublicKey  *ecdh.PublicKey
	enterpriseRsaPublicKey *rsa.PublicKey
	isEnterpriseAdmin      bool
	license                *proto_account_summary.License
	settings               *proto_account_summary.Settings
	enforcements           *proto_account_summary.Enforcements
}

func (ac *authContext) Username() string {
	return ac.username
}
func (ac *authContext) AccountUid() string {
	return ac.accountUid
}
func (ac *authContext) SessionToken() []byte {
	return ac.sessionToken
}
func (ac *authContext) SessionRestriction() SessionRestriction {
	return ac.sessionRestriction
}
func (ac *authContext) DataKey() []byte {
	return ac.dataKey
}
func (ac *authContext) SsoLoginInfo() ISsoLoginInfo {
	return ac.ssoLoginInfo
}
func (ac *authContext) DeviceToken() []byte {
	return ac.deviceToken
}
func (ac *authContext) DevicePrivateKey() *ecdh.PrivateKey {
	return ac.devicePrivateKey
}
func (ac *authContext) ClientKey() []byte {
	return ac.clientKey
}
func (ac *authContext) RsaPrivateKey() *rsa.PrivateKey {
	return ac.rsaPrivateKey
}
func (ac *authContext) EcPrivateKey() *ecdh.PrivateKey {
	return ac.ecPrivateKey
}
func (ac *authContext) EcPublicKey() *ecdh.PublicKey {
	return ac.ecPublicKey
}
func (ac *authContext) EnterpriseEcPublicKey() *ecdh.PublicKey {
	return ac.enterpriseEcPublicKey
}
func (ac *authContext) EnterpriseRsaPublicKey() *rsa.PublicKey {
	return ac.enterpriseRsaPublicKey
}
func (ac *authContext) IsEnterpriseAdmin() bool {
	return ac.isEnterpriseAdmin
}
func (ac *authContext) License() *proto_account_summary.License {
	return ac.license
}
func (ac *authContext) Settings() *proto_account_summary.Settings {
	return ac.settings
}
func (ac *authContext) Enforcements() *proto_account_summary.Enforcements {
	return ac.enforcements
}

type timeToKeepalive struct {
	lastActivity     int64
	logoutTimeoutMin int64
}

func (ttk *timeToKeepalive) updateTimeOfLastActivity() {
	ttk.lastActivity = time.Now().Unix() / 60
}
func (ttk *timeToKeepalive) checkKeepalive() bool {
	var now = time.Now().Unix() / 60
	return (now - ttk.lastActivity) > (ttk.logoutTimeoutMin / 3)
}

func newTimeToKeepalive(ac IAuthContext) *timeToKeepalive {
	var result = &timeToKeepalive{
		lastActivity:     time.Now().Unix() / 60,
		logoutTimeoutMin: 60,
	}
	if ac.Settings() != nil && ac.Settings().LogoutTimer > 0 {
		result.logoutTimeoutMin = ac.Settings().LogoutTimer / (1000 * 60)
	}
	if ac.Enforcements() != nil {
		for _, l := range ac.Enforcements().Longs {
			if l.Key == "logout_timer_desktop" {
				if l.GetValue() < result.logoutTimeoutMin {
					result.logoutTimeoutMin = l.GetValue()
				}
				break
			}
		}
	}
	if result.logoutTimeoutMin < 3 {
		result.logoutTimeoutMin = 3
	}
	return result
}

type keeperAuth struct {
	endpoint          IKeeperEndpoint
	authContext       *authContext
	pushNotifications IPushEndpoint
	ttk               *timeToKeepalive
}

func (ka *keeperAuth) keepAlive() {
	var err error
	if err = ka.ExecuteAuthRest("keep_alive", nil, nil); err != nil {
		ka.ttk.updateTimeOfLastActivity()
	}
}
func (ka *keeperAuth) OnIdle() {
	if ka.ttk.checkKeepalive() {
		go ka.keepAlive()
	}
}
func (ka *keeperAuth) Close() (err error) {
	if ka.pushNotifications != nil {
		if !ka.pushNotifications.IsClosed() {
			err = ka.pushNotifications.Close()
		}
		ka.pushNotifications = nil
	}
	return
}
func (ka *keeperAuth) PushNotifications() IPushEndpoint {
	return ka.pushNotifications
}

func (ka *keeperAuth) Endpoint() IKeeperEndpoint {
	return ka.endpoint
}
func (ka *keeperAuth) AuthContext() IAuthContext {
	return ka.authContext
}
func (ka *keeperAuth) executeV2Command(request api.IKeeperCommand, response api.IKeeperResponse) (err error) {
	var logger = api.GetLogger()
	var apiRq = request.GetAuthorizedCommand()
	apiRq.ClientVersion = ka.endpoint.ClientVersion()
	apiRq.Locale = ka.endpoint.Locale()
	if apiRq.Command == "" {
		apiRq.Command = request.CommandName()
	}
	var rqBody []byte
	if rqBody, err = json.Marshal(request); err == nil {
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debug("[RQ]", zap.ByteString("request", rqBody))
		}
		var rsBody []byte
		if rsBody, err = ka.endpoint.CommunicateKeeper("vault/execute_v2_command", rqBody, nil); err == nil {
			if err = json.Unmarshal(rsBody, response); err == nil {
				if logger.Level().Enabled(zap.DebugLevel) {
					logger.Debug("[RS]", zap.ByteString("request", rsBody))
				}
			}
		}
	}
	return
}

func (ka *keeperAuth) ExecuteAuthCommand(request api.IKeeperCommand, response api.IKeeperResponse, throwOnError bool) (err error) {
	var authCommand = request.GetAuthorizedCommand()
	authCommand.Username = ka.authContext.Username()
	authCommand.SessionToken = api.Base64UrlEncode(ka.authContext.SessionToken())
	if err = ka.executeV2Command(request, response); err != nil {
		return
	}
	ka.ttk.updateTimeOfLastActivity()
	if response != nil {
		authRs := response.GetKeeperApiResponse()
		if !authRs.IsSuccess() && throwOnError {
			err = api.NewKeeperApiError(authRs.ResultCode, authRs.Message)
		}
	}
	return
}
func (ka *keeperAuth) ExecuteAuthRest(path string, request proto.Message, response proto.Message) (err error) {
	var logger = api.GetLogger()
	var data []byte
	if request != nil {
		if data, err = proto.Marshal(request); err != nil {
			logger.Warn("Marshal protobuf error", zap.Error(err))
			return
		}
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debug("[RQ] "+path, zap.String("request", protojson.Format(request)))
		}
	}
	if data, err = ka.Endpoint().CommunicateKeeper(path, data, ka.authContext.SessionToken()); err != nil {
		return
	}
	ka.ttk.updateTimeOfLastActivity()
	if response != nil {
		if data != nil {
			if err = proto.Unmarshal(data, response); err != nil {
				logger.Warn("Unmarshal protobuf error", zap.Error(err))
				return
			}
			if logger.Level().Enabled(zap.DebugLevel) {
				logger.Debug("[RS] "+path, zap.String("response", protojson.Format(response)))
			}
		} else {
			logger.Warn("API path does not support response", zap.String("path", path))
			err = api.NewKeeperError(fmt.Sprintf("API path %s does not support response", path))
		}
	}
	return
}
func (ka *keeperAuth) ExecuteBatch(requests []api.IKeeperCommand) (responses []*api.KeeperApiResponse, err error) {
	var logger = api.GetLogger()
	for _, rq := range requests {
		var authCommand = rq.GetAuthorizedCommand()
		if len(authCommand.Command) == 0 {
			authCommand.Command = rq.CommandName()
		}
	}
	var attempt = 0
	for len(requests) > len(responses) {
		attempt += 1
		if attempt > 5 {
			break
		}
		var rq = &json_commands.ExecuteCommand{
			Requests: requests[len(responses):],
		}
		var rs = new(json_commands.ExecuteResponse)
		if err = ka.ExecuteAuthCommand(rq, rs, true); err != nil {
			return
		}
		if len(rs.Responses) < len(rq.Requests) {
			var lastRs = rs.Responses[len(rs.Responses)-1]
			if lastRs.ResultCode == "throttled" {
				logger.Info("Throttled. Sleeping for 10 seconds...")
				time.Sleep(time.Second * 10)
				if len(rs.Responses) > 1 {
					responses = append(responses, rs.Responses[:len(rs.Responses)-1]...)
				}
			} else {
				responses = append(responses, rs.Responses...)
			}
		} else {
			responses = append(responses, rs.Responses...)
		}
	}
	return
}
