package auth

import (
	"encoding/json"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"go.uber.org/zap"
	"os"
	"strings"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ IUserConfiguration       = &jsonUser{}
	_ IDeviceConfiguration     = &jsonDevice{}
	_ IUserDeviceConfiguration = &jsonUserDevice{}
	_ IServerConfiguration     = &jsonServer{}
	_ IKeeperConfiguration     = &jsonConfiguration{}
)

type sliceCollectionWrapper[JT any, T IEntityId] struct {
	pSlice   *[]*JT
	onClone  func(T) *JT
	onAdjust func(string) string
}

func (w *sliceCollectionWrapper[JT, T]) Get(id string) (result T) {
	var r T
	var ok bool
	if w.onAdjust != nil {
		id = w.onAdjust(id)
	}
	for _, e := range *w.pSlice {
		if r, ok = interface{}(e).(T); ok {
			if r.Id() == id {
				result = r
				break
			}
		}
	}
	return
}

func (w *sliceCollectionWrapper[JT, T]) Put(elem T) {
	id := elem.Id()
	var added = false
	for i, e := range *w.pSlice {
		if iid, ok := interface{}(e).(T); ok {
			if iid.Id() == id {
				(*w.pSlice)[i] = w.onClone(elem)
				added = true
				break
			}
		}
	}
	if !added {
		*w.pSlice = append(*w.pSlice, w.onClone(elem))
	}
}

func (w *sliceCollectionWrapper[JT, T]) Delete(id string) {
	var length = len(*w.pSlice)
	for i, e := range *w.pSlice {
		if iid, ok := interface{}(e).(T); ok {
			if iid.Id() == id {
				if i+1 < length {
					(*w.pSlice)[i] = (*w.pSlice)[length-1]
				}
				*w.pSlice = (*w.pSlice)[0 : length-1]
			}
		}
	}
}

func (w *sliceCollectionWrapper[JT, T]) List(cb func(T) bool) {
	for _, e := range *w.pSlice {
		if iid, ok := interface{}(e).(T); ok {
			if !cb(iid) {
				return
			}
		}
	}
}

type jsonDeviceServer struct {
	Server_    string `json:"server,omitempty"`
	CloneCode_ string `json:"clone_code,omitempty"`
}

func (jds *jsonDeviceServer) Server() string {
	return jds.Server_
}
func (jds *jsonDeviceServer) CloneCode() string {
	return jds.CloneCode_
}
func (jds *jsonDeviceServer) Id() string {
	return jds.Server()
}

type jsonDevice struct {
	DeviceToken_ string              `json:"device_token,omitempty"`
	PrivateKey_  string              `json:"private_key,omitempty"`
	ServerInfo_  []*jsonDeviceServer `json:"server_info,omitempty"`
	serverInfo   *sliceCollectionWrapper[jsonDeviceServer, IDeviceServerConfiguration]
}

func (d *jsonDevice) DeviceToken() string {
	return d.DeviceToken_
}
func (d *jsonDevice) DeviceKey() []byte {
	if len(d.PrivateKey_) == 0 {
		return nil
	}
	return api.Base64UrlDecode(d.PrivateKey_)
}
func (d *jsonDevice) ServerInfo() IConfigurationCollection[IDeviceServerConfiguration] {
	if d.serverInfo == nil {
		d.serverInfo = &sliceCollectionWrapper[jsonDeviceServer, IDeviceServerConfiguration]{
			pSlice: &d.ServerInfo_,
			onClone: func(other IDeviceServerConfiguration) *jsonDeviceServer {
				return &jsonDeviceServer{
					Server_:    other.Server(),
					CloneCode_: other.CloneCode(),
				}
			},
			onAdjust: AdjustServerName,
		}
	}
	return d.serverInfo
}
func (d *jsonDevice) Id() string {
	return d.DeviceToken()
}

type jsonServer struct {
	Server_      string `json:"server,omitempty"`
	ServerKeyID_ int32  `json:"server_key_id"`
}

func (s *jsonServer) Id() string {
	return strings.ToLower(s.Server_)
}
func (s *jsonServer) Server() string {
	return s.Server_
}
func (s *jsonServer) ServerKeyId() int32 {
	return s.ServerKeyID_
}

type jsonUserDevice struct {
	DeviceToken_ string `json:"device_token,omitempty"`
}

func (ud *jsonUserDevice) DeviceToken() string {
	return ud.DeviceToken_
}

func (ud *jsonUserDevice) Id() string {
	return ud.DeviceToken_
}

type jsonUser struct {
	User_         string          `json:"user,omitempty"`
	UserPassword_ string          `json:"password,omitempty"`
	Server_       string          `json:"server,omitempty"`
	LastDevice_   *jsonUserDevice `json:"last_device,omitempty"`
}

func (u *jsonUser) Id() string {
	return strings.ToLower(u.User_)
}
func (u *jsonUser) Username() string {
	return u.User_
}
func (u *jsonUser) Password() string {
	return u.UserPassword_
}
func (u *jsonUser) Server() string {
	return u.Server_
}
func (u *jsonUser) LastDevice() IUserDeviceConfiguration {
	return u.LastDevice_
}

type jsonConfiguration struct {
	LastLogin_  string        `json:"last_login,omitempty"`
	LastServer_ string        `json:"last_server,omitempty"`
	Devices_    []*jsonDevice `json:"devices,omitempty"`
	Servers_    []*jsonServer `json:"servers,omitempty"`
	Users_      []*jsonUser   `json:"users,omitempty"`
	users       *sliceCollectionWrapper[jsonUser, IUserConfiguration]
	servers     *sliceCollectionWrapper[jsonServer, IServerConfiguration]
	devices     *sliceCollectionWrapper[jsonDevice, IDeviceConfiguration]
}

func (j *jsonConfiguration) LastLogin() string {
	return j.LastLogin_
}
func (j *jsonConfiguration) SetLastLogin(lastLogin string) {
	j.LastLogin_ = lastLogin
}
func (j *jsonConfiguration) LastServer() string {
	return j.LastServer_
}
func (j *jsonConfiguration) SetLastServer(lastServer string) {
	j.LastServer_ = lastServer
}
func (j *jsonConfiguration) Users() IConfigurationCollection[IUserConfiguration] {
	if j.users == nil {
		j.users = &sliceCollectionWrapper[jsonUser, IUserConfiguration]{
			pSlice: &j.Users_,
			onClone: func(other IUserConfiguration) *jsonUser {
				var ju = &jsonUser{
					User_:         other.Username(),
					UserPassword_: other.Password(),
					Server_:       other.Server(),
					LastDevice_:   nil,
				}
				var ld = other.LastDevice()
				if ld != nil {
					ju.LastDevice_ = &jsonUserDevice{
						DeviceToken_: ld.DeviceToken(),
					}
				}
				return ju
			},
			onAdjust: AdjustUserName,
		}
	}
	return j.users
}
func (j *jsonConfiguration) Servers() IConfigurationCollection[IServerConfiguration] {
	if j.servers == nil {
		j.servers = &sliceCollectionWrapper[jsonServer, IServerConfiguration]{
			pSlice: &j.Servers_,
			onClone: func(other IServerConfiguration) *jsonServer {
				return &jsonServer{
					Server_:      other.Server(),
					ServerKeyID_: other.ServerKeyId(),
				}
			},
			onAdjust: AdjustServerName,
		}
	}
	return j.servers
}
func (j *jsonConfiguration) Devices() IConfigurationCollection[IDeviceConfiguration] {
	if j.devices == nil {
		j.devices = &sliceCollectionWrapper[jsonDevice, IDeviceConfiguration]{
			pSlice: &j.Devices_,
			onClone: func(other IDeviceConfiguration) *jsonDevice {
				var jd = &jsonDevice{
					DeviceToken_: other.DeviceToken(),
					PrivateKey_:  api.Base64UrlEncode(other.DeviceKey()),
				}
				if other.ServerInfo() != nil {
					other.ServerInfo().List(func(dsc IDeviceServerConfiguration) bool {
						jd.ServerInfo().Put(dsc)
						return true
					})
				}
				return jd
			},
		}
	}
	return j.devices
}

type jsonConfigurationFileLoader struct {
	filePath string
}

func NewJsonConfigurationFileLoader(filename string) IJsonConfigurationLoader {
	if filename == "" {
		filename = "config.json"
	}
	return &jsonConfigurationFileLoader{
		filePath: api.GetKeeperFileFullPath(filename),
	}
}
func (fl *jsonConfigurationFileLoader) LoadJson() (data []byte, err error) {
	if _, err = os.Stat(fl.filePath); err == nil {
		data, err = os.ReadFile(fl.filePath)
	} else {
		data = []byte("{}")
		err = nil
	}
	return
}

func (fl *jsonConfigurationFileLoader) StoreJson(data []byte) (err error) {
	if err = os.WriteFile(fl.filePath, data, 0755); err != nil {
		api.GetLogger().Warn("Write JSON configuration to file error.", zap.Error(err))
	}
	return
}

type jsonConfigurationStorage struct {
	loader IJsonConfigurationLoader
}

func (js *jsonConfigurationStorage) Get() (configuration IKeeperConfiguration, err error) {
	var data []byte
	if data, err = js.loader.LoadJson(); err != nil {
		return
	}
	var config = &jsonConfiguration{}
	if err = json.Unmarshal(data, config); err != nil {
		return
	}
	return config, nil
}
func (js *jsonConfigurationStorage) Put(configuration IKeeperConfiguration) (err error) {
	var jsonConfig = &jsonConfiguration{}
	CopyConfiguration(configuration, jsonConfig)
	var data []byte
	if data, err = json.MarshalIndent(jsonConfig, "", "  "); err == nil {
		err = js.loader.StoreJson(data)
	}
	return
}

func NewJsonConfigurationStorage(loader IJsonConfigurationLoader) IConfigurationStorage {
	return &jsonConfigurationStorage{
		loader: loader,
	}
}
func NewJsonConfigurationFile(filePath string) IConfigurationStorage {
	return NewJsonConfigurationStorage(NewJsonConfigurationFileLoader(filePath))
}
