package auth

import (
	"net/url"
	"strings"
)

func AdjustUserName(username string) string {
	return strings.ToLower(username)
}

func AdjustServerName(servername string) string {
	u, err := url.Parse(servername)
	if err == nil {
		if u.Host != "" {
			return strings.ToLower(u.Host)
		}
		if u.Path != "" {
			return strings.ToLower(u.Path)
		}
	}
	return strings.ToLower(servername)
}

type IEntityId interface {
	Id() string
}

type IConfigurationCollection[T IEntityId] interface {
	Get(string) T
	Put(T)
	Delete(string)
	List(func(T) bool)
}

type IUserDeviceConfiguration interface {
	IEntityId
	DeviceToken() string
}

type IUserConfiguration interface {
	IEntityId
	Username() string
	Password() string
	Server() string
	LastDevice() IUserDeviceConfiguration
}

type IServerConfiguration interface {
	IEntityId
	Server() string
	ServerKeyId() int32
}

type IDeviceServerConfiguration interface {
	IEntityId
	Server() string
	CloneCode() string
}

type IDeviceConfiguration interface {
	IEntityId
	DeviceToken() string
	DeviceKey() []byte
	ServerInfo() IConfigurationCollection[IDeviceServerConfiguration]
}

type IKeeperConfiguration interface {
	Users() IConfigurationCollection[IUserConfiguration]
	Servers() IConfigurationCollection[IServerConfiguration]
	Devices() IConfigurationCollection[IDeviceConfiguration]

	LastLogin() string
	SetLastLogin(string)

	LastServer() string
	SetLastServer(string)
}

type IConfigurationStorage interface {
	Get() (IKeeperConfiguration, error)
	Put(IKeeperConfiguration) error
}

/*
type IConfigurationProtection interface {
	Obscure(string) (string, error)
	Clarify(string) (string, error)
}

type IConfigurationProtectionFactory interface {
	Resolve(string) IConfigurationProtection
}

type IExternalConfigurationStorage interface {
	IEntityId

	SecurityAlgorithm() string
	SetSecurityAlgorithm(string)

	ConfigurationProtection() IConfigurationProtectionFactory
	SetConfigurationProtection(IConfigurationProtectionFactory)

	Flush()
}
*/

// IMPLEMENTATION

type genericCollection[T IEntityId] struct {
	data map[string]T
}

func (c *genericCollection[T]) Get(id string) (result T) {
	if c.data != nil {
		return c.data[id]
	}
	return
}

func (c *genericCollection[T]) Put(elem T) {
	if c.data == nil {
		c.data = make(map[string]T)
	}
	c.data[elem.Id()] = elem
}

func (c *genericCollection[T]) Delete(id string) {
	if c.data != nil {
		delete(c.data, id)
	}
}

func (c *genericCollection[T]) List(cb func(T) bool) {
	if c.data != nil {
		ff := len(c.data)
		keys := make([]string, 0, ff)
		for k := range c.data {
			keys = append(keys, k)
		}
		for _, key := range keys {
			if e, ok := c.data[key]; ok {
				if !cb(e) {
					return
				}
			}
		}
	}
}

type UserDeviceConfiguration struct {
	deviceToken string
}

func NewUserDeviceConfiguration(deviceToken string) *UserDeviceConfiguration {
	return &UserDeviceConfiguration{
		deviceToken: deviceToken,
	}
}
func CloneUserDeviceConfiguration(other IUserDeviceConfiguration) *UserDeviceConfiguration {
	return &UserDeviceConfiguration{
		deviceToken: other.DeviceToken(),
	}
}
func (ud *UserDeviceConfiguration) DeviceToken() string {
	return ud.deviceToken
}
func (ud *UserDeviceConfiguration) Id() string {
	return ud.DeviceToken()
}

type UserConfiguration struct {
	username   string
	server     string
	password   string
	lastDevice *UserDeviceConfiguration
}

func NewUserConfiguration(username string) *UserConfiguration {
	return &UserConfiguration{
		username: AdjustUserName(username),
	}
}
func CloneUserConfiguration(other IUserConfiguration) *UserConfiguration {
	var u = &UserConfiguration{
		username: other.Username(),
		server:   other.Server(),
	}
	if other.LastDevice() != nil {
		u.lastDevice = CloneUserDeviceConfiguration(other.LastDevice())
	}
	return u
}
func (u *UserConfiguration) Id() string {
	return u.username
}
func (u *UserConfiguration) Username() string {
	return u.username
}
func (u *UserConfiguration) Password() string {
	return u.password
}
func (u *UserConfiguration) SetPassword(password string) {
	u.password = password
}
func (u *UserConfiguration) Server() string {
	return u.server
}
func (u *UserConfiguration) SetServer(server string) {
	u.server = AdjustServerName(server)
}
func (u *UserConfiguration) LastDevice() IUserDeviceConfiguration {
	return u.lastDevice
}
func (u *UserConfiguration) SetLastDevice(lastDevice IUserDeviceConfiguration) {
	if lastDevice != nil {
		u.lastDevice = CloneUserDeviceConfiguration(lastDevice)
	} else {
		u.lastDevice = nil
	}
}

type ServerConfiguration struct {
	server      string
	serverKeyId int32
}

func NewServerConfiguration(server string) *ServerConfiguration {
	return &ServerConfiguration{
		server:      AdjustServerName(server),
		serverKeyId: 7,
	}
}
func CloneServerConfiguration(other IServerConfiguration) *ServerConfiguration {
	return &ServerConfiguration{
		server:      other.Server(),
		serverKeyId: other.ServerKeyId(),
	}
}
func (s *ServerConfiguration) Id() string {
	return s.server
}
func (s *ServerConfiguration) Server() string {
	return s.server
}
func (s *ServerConfiguration) ServerKeyId() int32 {
	return s.serverKeyId
}
func (s *ServerConfiguration) SetServerKeyId(keyId int32) {
	s.serverKeyId = keyId
}

type DeviceServerConfiguration struct {
	server    string
	cloneCode string
}

func NewDeviceServerConfiguration(server string) *DeviceServerConfiguration {
	return &DeviceServerConfiguration{
		server: AdjustServerName(server),
	}
}
func CloneDeviceServerConfiguration(other IDeviceServerConfiguration) *DeviceServerConfiguration {
	return &DeviceServerConfiguration{
		server:    other.Server(),
		cloneCode: other.CloneCode(),
	}
}
func (ds *DeviceServerConfiguration) Id() string {
	return strings.ToLower(ds.server)
}
func (ds *DeviceServerConfiguration) Server() string {
	return ds.server
}
func (ds *DeviceServerConfiguration) CloneCode() string {
	return ds.cloneCode
}
func (ds *DeviceServerConfiguration) SetCloneCode(cloneCode string) {
	ds.cloneCode = cloneCode
}

type DeviceConfiguration struct {
	deviceToken string
	deviceKey   []byte
	serverInfo  *genericCollection[IDeviceServerConfiguration]
}

func NewDeviceConfiguration(deviceToken string, deviceKey []byte) *DeviceConfiguration {
	return &DeviceConfiguration{
		deviceToken: deviceToken,
		deviceKey:   deviceKey,
		serverInfo:  &genericCollection[IDeviceServerConfiguration]{},
	}
}
func CloneDeviceConfiguration(other IDeviceConfiguration) *DeviceConfiguration {
	var d = NewDeviceConfiguration(other.DeviceToken(), other.DeviceKey())
	if other.ServerInfo() != nil {
		d.serverInfo = &genericCollection[IDeviceServerConfiguration]{}
		other.ServerInfo().List(func(elem IDeviceServerConfiguration) bool {
			dsc := CloneDeviceServerConfiguration(elem)
			d.serverInfo.Put(dsc)
			return true
		})
	}
	return d
}
func (d *DeviceConfiguration) Id() string {
	return d.deviceToken
}
func (d *DeviceConfiguration) DeviceToken() string {
	return d.deviceToken
}
func (d *DeviceConfiguration) DeviceKey() []byte {
	return d.deviceKey
}
func (d *DeviceConfiguration) ServerInfo() IConfigurationCollection[IDeviceServerConfiguration] {
	if d.serverInfo == nil {
		d.serverInfo = &genericCollection[IDeviceServerConfiguration]{}
	}
	return d.serverInfo
}

type KeeperConfiguration struct {
	lastLogin  string
	lastServer string
	users      *genericCollection[IUserConfiguration]
	servers    *genericCollection[IServerConfiguration]
	devices    *genericCollection[IDeviceConfiguration]
}

func (c *KeeperConfiguration) LastLogin() string {
	return c.lastLogin
}
func (c *KeeperConfiguration) SetLastLogin(lastLogin string) {
	c.lastLogin = lastLogin
}
func (c *KeeperConfiguration) LastServer() string {
	return c.lastServer
}
func (c *KeeperConfiguration) SetLastServer(lastServer string) {
	c.lastServer = lastServer
}
func (c *KeeperConfiguration) Users() IConfigurationCollection[IUserConfiguration] {
	if c.users == nil {
		c.users = &genericCollection[IUserConfiguration]{}
	}
	return c.users
}
func (c *KeeperConfiguration) Servers() IConfigurationCollection[IServerConfiguration] {
	if c.servers == nil {
		c.servers = &genericCollection[IServerConfiguration]{}
	}
	return c.servers
}
func (c *KeeperConfiguration) Devices() IConfigurationCollection[IDeviceConfiguration] {
	if c.devices == nil {
		c.devices = &genericCollection[IDeviceConfiguration]{}
	}
	return c.devices
}

func NewKeeperConfiguration() *KeeperConfiguration {
	return &KeeperConfiguration{}
}

func CloneKeeperConfiguration(other IKeeperConfiguration) *KeeperConfiguration {
	var conf = &KeeperConfiguration{}
	CopyConfiguration(other, conf)
	return conf
}

type inMemoryConfigurationStorage struct {
	configuration IKeeperConfiguration
}

func (cs *inMemoryConfigurationStorage) Get() (IKeeperConfiguration, error) {
	return cs.configuration, nil
}

func (cs *inMemoryConfigurationStorage) Put(configuration IKeeperConfiguration) error {
	cs.configuration = CloneKeeperConfiguration(configuration)
	return nil
}

func NewInMemoryConfigurationStorage(configuration IKeeperConfiguration) IConfigurationStorage {
	return &inMemoryConfigurationStorage{
		configuration: CloneKeeperConfiguration(configuration),
	}
}

func CopyConfiguration(fromConfig IKeeperConfiguration, toConfig IKeeperConfiguration) {
	toConfig.SetLastLogin(fromConfig.LastLogin())
	toConfig.SetLastServer(fromConfig.LastServer())
	fromConfig.Users().List(func(uc IUserConfiguration) bool {
		toConfig.Users().Put(uc)
		return true
	})
	fromConfig.Devices().List(func(dc IDeviceConfiguration) bool {
		toConfig.Devices().Put(dc)
		return true
	})
	fromConfig.Servers().List(func(sc IServerConfiguration) bool {
		toConfig.Servers().Put(sc)
		return true
	})
}

type IJsonConfigurationLoader interface {
	LoadJson() ([]byte, error)
	StoreJson([]byte) error
}
