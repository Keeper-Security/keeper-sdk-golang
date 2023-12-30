package vault

import (
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	"io"
)

var (
	_ IStorageRecord                 = &database.RecordStorage{}
	_ IStorageNonSharedData          = &database.NonSharedDataStorage{}
	_ IStorageSharedFolder           = &database.SharedFolderStorage{}
	_ IStorageTeam                   = &database.TeamStorage{}
	_ IStorageFolder                 = &database.FolderStorage{}
	_ IStorageRecordType             = &database.RecordTypeStorage{}
	_ IStorageUserEmail              = &database.UserEmailStorage{}
	_ IStorageRecordKey              = &database.RecordKeyStorage{}
	_ IStorageSharedFolderKey        = &database.SharedFolderKeyStorage{}
	_ IStorageSharedFolderPermission = &database.SharedFolderPermissionStorage{}
	_ IStorageFolderRecord           = &database.FolderRecordStorage{}
	_ IStorageBreachWatchRecord      = &database.BreachWatchRecordStorage{}
	_ IStorageSecurityData           = &database.BreachWatchSecurityData{}
)

type IUserSettings interface {
	ContinuationToken() []byte
	ProfileData() []byte
	ProfileName() string
	ProfileUrl() string
	SetContinuationToken([]byte)
	SetProfileData([]byte)
	SetProfileName(string)
	SetProfileUrl(string)
}

type StorageKeyType int32

const (
	StorageKeyType_UserClientKey_AES_GCM   StorageKeyType = 1 // AES GSM: user client key
	StorageKeyType_User_RSA_PrivateKey     StorageKeyType = 2 // RSA: user RSA key
	StorageKeyType_User_EC_PrivateKey      StorageKeyType = 3 // EC: user EC private key
	StorageKeyType_SharedFolderKey_AES_Any StorageKeyType = 4
	StorageKeyType_TeamKey_AES_GCM         StorageKeyType = 5
	StorageKeyType_TeamRsaPrivateKey       StorageKeyType = 6
	StorageKeyType_RecordKey_AES_GCM       StorageKeyType = 7
)

type IStorageRecord interface {
	RecordUid() string
	Revision() int64
	Version() int32
	ModifiedTime() int64
	Data() []byte
	Extra() []byte
	UData() string
	Shared() bool
	SetShared(bool)
	storage.IUid[string]
}

type IStorageNonSharedData interface {
	RecordUid() string
	Data() []byte
	storage.IUid[string]
}

type IStorageSharedFolder interface {
	SharedFolderUid() string
	Revision() int64
	Name() []byte
	Data() []byte
	DefaultManageRecords() bool
	DefaultManageUsers() bool
	DefaultCanEdit() bool
	DefaultCanShare() bool
	OwnerAccountUid() string
	storage.IUid[string]
}

type IStorageTeam interface {
	TeamUid() string
	Name() string
	TeamKey() []byte
	KeyType() int32
	TeamPrivateKey() []byte
	RestrictEdit() bool
	RestrictShare() bool
	RestrictView() bool
	storage.IUid[string]
}

type IStorageFolder interface {
	FolderUid() string
	ParentUid() string
	SharedFolderUid() string
	FolderType() string
	FolderKey() []byte
	KeyType() int32
	Data() []byte
	Revision() int64
	storage.IUid[string]
}

type IStorageUserEmail interface {
	AccountUid() string
	Email() string
	storage.IUidLink[string, string]
}

type IStorageRecordKey interface {
	RecordUid() string
	EncrypterUid() string
	KeyType() int32
	RecordKey() []byte
	CanShare() bool
	CanEdit() bool
	Owner() bool
	OwnerAccountUid() string
	ExpirationTime() int64
	storage.IUidLink[string, string]
}

type IStorageSharedFolderKey interface {
	SharedFolderUid() string
	EncrypterUid() string
	KeyType() int32
	SharedFolderKey() []byte
	storage.IUidLink[string, string]
}

type SharedFolderUserType int32

const (
	SharedFolderUserType_User SharedFolderUserType = 1
	SharedFolderUserType_Team SharedFolderUserType = 2
)

type IStorageSharedFolderPermission interface {
	SharedFolderUid() string
	UserUid() string
	UserType() int32
	ManageRecords() bool
	ManageUsers() bool
	ExpirationTime() int64
	storage.IUidLink[string, string]
}

type IStorageFolderRecord interface {
	FolderUid() string // subject
	RecordUid() string // object
	storage.IUidLink[string, string]
}

type IStorageBreachWatchRecord interface {
	RecordUid() string
	Data() []byte
	Type() int32
	Revision() int64
	storage.IUid[string]
}

type IStorageSecurityData interface {
	RecordUid() string
	Revision() int64
	storage.IUid[string]
}

type RecordTypeScope int32

const (
	RecordTypeScope_Standard         RecordTypeScope = 0
	RecordTypeScope_User             RecordTypeScope = 1
	RecordTypeScope_Enterprise       RecordTypeScope = 2
	RecordTypeScope_Pam              RecordTypeScope = 3
	RecordTypeScope_PamConfiguration RecordTypeScope = 4
)

type IStorageRecordType interface {
	Id() int64
	Scope() int32
	Content() string
	storage.IUid[int64]
}

type IPendingShareStoragePlugin interface {
	PendingShares() []string
	AddPendingShares([]string)
}

type IVaultStorage interface {
	PersonalScopeUid() string
	UserSettings() storage.IRecordStorage[IUserSettings]
	Records() storage.IEntityStorage[IStorageRecord, string]
	RecordTypes() storage.IEntityStorage[IStorageRecordType, int64]
	SharedFolders() storage.IEntityStorage[IStorageSharedFolder, string]
	Teams() storage.IEntityStorage[IStorageTeam, string]
	UserEmails() storage.ILinkStorage[IStorageUserEmail, string, string]
	NonSharedData() storage.IEntityStorage[IStorageNonSharedData, string]
	RecordKeys() storage.ILinkStorage[IStorageRecordKey, string, string]
	SharedFolderKeys() storage.ILinkStorage[IStorageSharedFolderKey, string, string]
	SharedFolderPermissions() storage.ILinkStorage[IStorageSharedFolderPermission, string, string]
	Folders() storage.IEntityStorage[IStorageFolder, string]
	FolderRecords() storage.ILinkStorage[IStorageFolderRecord, string, string]
	BreachWatchRecords() storage.IEntityStorage[IStorageBreachWatchRecord, string]

	Clear()

	PendingSharesPlugin() IPendingShareStoragePlugin
	SetPendingSharesPlugin(IPendingShareStoragePlugin)
	io.Closer
}
