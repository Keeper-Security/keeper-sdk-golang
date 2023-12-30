package enterprise

import (
	"crypto/ecdh"
	"crypto/rsa"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/auth"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	"github.com/keeper-security/keeper-sdk-golang/vault"
)

type INode interface {
	NodeId() int64
	Name() string
	ParentId() int64
	BridgeId() int64
	ScimId() int64
	LicenseId() int64
	DuoEnabled() bool
	RsaEnabled() bool
	RestrictVisibility() bool
	SsoServiceProviderId() []int64
	EncryptedData() string
	storage.IUid[int64]
}

type INodeEdit interface {
	INode
	SetName(string)
	SetParentId(int64)
	SetBridgeId(int64)
	SetScimId(int64)
	SetCloudSsoId(int64)
	SetRestrictVisibility(bool)
}

type IRole interface {
	RoleId() int64
	Name() string
	NodeId() int64
	KeyType() string
	VisibleBelow() bool
	NewUserInherit() bool
	RoleType() string
	EncryptedData() string
	storage.IUid[int64]
}

type IRoleEdit interface {
	IRole
	SetName(string)
	SetNodeId(int64)
	SetKeyType(string)
	SetVisibleBelow(bool)
	SetNewUserInherit(bool)
}

type UserLock int32

const (
	UserLock_Unlocked UserLock = 0
	UserLock_Locked   UserLock = 1
	UserLock_Disabled UserLock = 2
)

type UserStatus string

const (
	UserStatus_Active   UserStatus = "active"
	UserStatus_Inactive UserStatus = "inactive"
)

type IUser interface {
	EnterpriseUserId() int64
	Username() string
	FullName() string
	JobTitle() string
	NodeId() int64
	Status() UserStatus
	Lock() UserLock
	UserId() int32
	AccountShareExpiration() int64
	TfaEnabled() bool
	TransferAcceptanceStatus() int32
	storage.IUid[int64]
}
type IUserEdit interface {
	IUser
	SetFullName(string)
	SetJobTitle(string)
	SetNodeId(int64)
	SetLock(UserLock)
}

type ITeam interface {
	TeamUid() string
	Name() string
	NodeId() int64
	RestrictEdit() bool
	RestrictShare() bool
	RestrictView() bool
	EncryptedTeamKey() []byte
	storage.IUid[string]
}

type ITeamEdit interface {
	ITeam
	SetName(string)
	SetNodeId(int64)
	SetRestrictEdit(bool)
	SetRestrictShare(bool)
	SetRestrictView(bool)
}

type ITeamUser interface {
	TeamUid() string
	EnterpriseUserId() int64
	UserType() string
	storage.IUidLink[string, int64]
}
type ITeamUserEdit interface {
	ITeamUser
	SetUserType(string)
}

type IRoleUser interface {
	RoleId() int64
	EnterpriseUserId() int64
	storage.IUidLink[int64, int64]
}

type IRoleTeam interface {
	RoleId() int64
	TeamUid() string
	storage.IUidLink[int64, string]
}

type IRolePrivilege interface {
	RoleId() int64
	ManagedNodeId() int64
	ManageNodes() bool
	ManageUsers() bool
	ManageRoles() bool
	ManageTeams() bool
	RunReports() bool
	ManageBridge() bool
	ApproveDevices() bool
	ManageRecordTypes() bool
	SharingAdministrator() bool
	RunComplianceReport() bool
	TransferAccount() bool
	ManageCompanies() bool
	ToSet() api.Set[string]
	storage.IUidLink[int64, int64]
}
type IRolePrivilegeEdit interface {
	IRolePrivilege
	SetManageNodes(bool)
	SetManageUsers(bool)
	SetManageRoles(bool)
	SetManageTeams(bool)
	SetRunReports(bool)
	SetManageBridge(bool)
	SetApproveDevices(bool)
	SetManageRecordTypes(bool)
	SetSharingAdministrator(bool)
	SetRunComplianceReport(bool)
	SetTransferAccount(bool)
	SetManageCompanies(bool)
	SetPrivilege(string, bool)
}
type IManagedNode interface {
	RoleId() int64
	ManagedNodeId() int64
	CascadeNodeManagement() bool
	storage.IUidLink[int64, int64]
}
type IManageNodeEdit interface {
	IManagedNode
	SetCascadeNodeManagement(bool)
}

type IRoleEnforcement interface {
	RoleId() int64
	EnforcementType() string
	Value() string
	storage.IUidLink[int64, string]
}
type IRoleEnforcementEdit interface {
	IRoleEnforcement
	SetValue(string)
}

type ILicenseAddOn interface {
	Name() string
	Enabled() bool
	IncludedInProduct() bool
	IsTrial() bool
	Seats() int32
	ApiCallCount() int32
	Created() int64
	ActivationTime() int64
	Expiration() int64
}
type IMcDefault interface {
	McProduct() string
	FilePlanType() string
	MaxLicenses() int32
	Addons() []string
	FixedMaxLicenses() bool
}
type IMspPermits interface {
	Restricted() bool
	MaxFilePlanType() string
	AllowUnlimitedLicenses() bool
	AllowedMcProducts() []string
	AllowedAddOns() []string
	McDefaults() []IMcDefault
}

type IMspContact interface {
	EnterpriseId() int32
	EnterpriseName() string
}

type ILicense interface {
	EnterpriseLicenseId() int64
	LicenseKeyId() int32
	ProductTypeId() int32
	FilePlanId() int32
	Name() string
	NumberOfSeats() int32
	SeatsAllocated() int32
	SeatsPending() int32
	AddOns() []ILicenseAddOn
	LicenseStatus() string
	NextBillingDate() int64
	Expiration() int64
	StorageExpiration() int64
	Distributor() bool
	MspPermits() []IMspPermits
	ManagedBy() IMspContact
	storage.IUid[int64]
}

type IUserAlias interface {
	EnterpriseUserId() int64
	Username() string
	storage.IUidLink[int64, string]
}

type ISsoService interface {
	SsoServiceProviderId() int64
	NodeId() int64
	Name() string
	SpUrl() string
	InviteNewUsers() bool
	Active() bool
	IsCloud() bool
	storage.IUid[int64]
}

type IBridge interface {
	BridgeId() int64
	NodeId() int64
	WanIpEnforcement() string
	LanIpEnforcement() string
	Status() string
	storage.IUid[int64]
}

type IScim interface {
	ScimId() int64
	NodeId() int64
	Status() string
	LastSynced() int64
	RolePrefix() string
	UniqueGroups() bool
	storage.IUid[int64]
}

type IEmailProvision interface {
	Id() int64
	NodeId() int64
	Domain() string
	Method() string
	storage.IUid[int64]
}

type IManagedCompany interface {
	McEnterpriseId() int64
	McEnterpriseName() string
	MspNodeId() int64
	NumberOfSeats() int32
	NumberOfUsers() int32
	ProductId() string
	IsExpired() bool
	TreeKey() string
	TreeKeyRole() int64
	FilePlanType() string
	AddOns() []ILicenseAddOn
	storage.IUid[int64]
}

type IQueuedTeam interface {
	TeamUid() string
	Name() string
	NodeId() int64
	EncryptedData() string
	storage.IUid[string]
}

type IQueuedTeamUser interface {
	TeamUid() string
	EnterpriseUserId() int64
	storage.IUidLink[string, int64]
}

type IEnterpriseStorage interface {
	ContinuationToken() ([]byte, error)
	SetContinuationToken([]byte) error
	EnterpriseIds() ([]int64, error)
	SetEnterpriseIds([]int64) error
	GetEntities(func(int32, []byte) bool) error
	PutEntity(int32, string, []byte) error
	DeleteEntity(int32, string, []byte) error
	Flush() error
	Clear()
}

type IEnterpriseInfo interface {
	EnterpriseName() string
	IsDistributor() bool
	TreeKey() []byte
	RsaPrivateKey() *rsa.PrivateKey
	EcPrivateKey() *ecdh.PrivateKey
}

type IEnterpriseEntity[T storage.IUid[K], K storage.Key] interface {
	GetAllEntities(func(T) bool)
	GetEntity(K) T
}

type IEnterpriseLink[T storage.IUidLink[KS, KO], KS storage.Key, KO storage.Key] interface {
	GetLink(KS, KO) T
	GetLinksBySubject(KS, func(T) bool)
	GetLinksByObject(KO, func(T) bool)
	GetAllLinks(func(T) bool)
}

type IEnterpriseData interface {
	EnterpriseInfo() IEnterpriseInfo
	Nodes() IEnterpriseEntity[INode, int64]
	Roles() IEnterpriseEntity[IRole, int64]
	Users() IEnterpriseEntity[IUser, int64]
	Teams() IEnterpriseEntity[ITeam, string]
	TeamUsers() IEnterpriseLink[ITeamUser, string, int64]
	QueuedTeams() IEnterpriseEntity[IQueuedTeam, string]
	QueuedTeamUsers() IEnterpriseLink[IQueuedTeamUser, string, int64]
	RoleUsers() IEnterpriseLink[IRoleUser, int64, int64]
	RoleTeams() IEnterpriseLink[IRoleTeam, int64, string]
	ManagedNodes() IEnterpriseLink[IManagedNode, int64, int64]
	RolePrivileges() IEnterpriseLink[IRolePrivilege, int64, int64]
	RoleEnforcements() IEnterpriseLink[IRoleEnforcement, int64, string]
	Licenses() IEnterpriseEntity[ILicense, int64]
	UserAliases() IEnterpriseLink[IUserAlias, int64, string]
	SsoServices() IEnterpriseEntity[ISsoService, int64]
	Bridges() IEnterpriseEntity[IBridge, int64]
	Scims() IEnterpriseEntity[IScim, int64]
	ManagedCompanies() IEnterpriseEntity[IManagedCompany, int64]
	RecordTypes() IEnterpriseEntity[vault.IRecordType, string]

	RootNode() INode
}

type IEnterpriseLoader interface {
	Storage() IEnterpriseStorage
	EnterpriseData() IEnterpriseData
	KeeperAuth() auth.IKeeperAuth
	LoadRoleKeys(map[int64][]byte) error
	Load() error
}

type IEnterpriseManagement interface {
	GetEnterpriseId() (int64, error)
	EnterpriseData() IEnterpriseData
	ModifyNodes(nodesToAdd []INode, nodesToUpdate []INode, nodesToDelete []int64) []error
	ModifyRoles(rolesToAdd []IRole, rolesToUpdate []IRole, rolesToDelete []int64) []error
	ModifyTeams(teamsToAdd []ITeam, teamsToUpdate []ITeam, teamsToDelete []string) []error
	ModifyTeamUsers(teamUsersToAdd []ITeamUser, teamUsersToRemove []ITeamUser) []error
	ModifyRoleUsers(roleUsersToAdd []IRoleUser, roleUsersToRemove []IRoleUser) []error
	ModifyRoleTeams(roleTeamsToAdd []IRoleTeam, roleTeamsToRemove []IRoleTeam) []error
	ModifyManagedNodes(managedNodesToAdd []IManagedNode, managedNodesToUpdate []IManagedNode, managedNodesToRemove []IManagedNode) []error
	ModifyRolePrivileges(privileges []IRolePrivilege) []error
	ModifyRoleEnforcements(enforcementsToSet []IRoleEnforcement) []error

	Commit() []error
}
