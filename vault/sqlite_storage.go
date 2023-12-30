package vault

import (
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/sqlite"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	"go.uber.org/zap"
	"reflect"
)

var (
	_ IVaultStorage = new(sqliteVaultStorage)
)

func NewSqliteVaultStorage(getter sqlite.ConnectionGetter, accountUid string) (storage IVaultStorage, err error) {
	var db = getter()
	var sqliteStorage = &sqliteVaultStorage{
		userAccountUid: accountUid,
	}
	var entityType reflect.Type
	var tableSchema sqlite.ITableSchema

	// User Settings
	entityType = reflect.TypeOf((*database.UserSettingsStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, nil, nil, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.userSettings, err = sqlite.NewSqliteRecordStorage[IUserSettings](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Records
	entityType = reflect.TypeOf((*database.RecordStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"record_uid"}, nil, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.records, err = sqlite.NewSqliteEntityStorage[IStorageRecord, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Record Types
	entityType = reflect.TypeOf((*database.RecordTypeStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"id"}, nil, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.recordTypes, err = sqlite.NewSqliteEntityStorage[IStorageRecordType, int64](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Shared Folders
	entityType = reflect.TypeOf((*database.SharedFolderStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"shared_folder_uid"}, nil, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.sharedFolders, err = sqlite.NewSqliteEntityStorage[IStorageSharedFolder, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Teams
	entityType = reflect.TypeOf((*database.TeamStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"team_uid"}, nil, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.teams, err = sqlite.NewSqliteEntityStorage[IStorageTeam, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// User Emails
	entityType = reflect.TypeOf((*database.UserEmailStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"account_uid", "email"}, map[string][]string{"Email": {"email"}}, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.userEmails, err = sqlite.NewSqliteLinkStorage[IStorageUserEmail, string, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Non Shared Data
	entityType = reflect.TypeOf((*database.NonSharedDataStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"record_uid"}, nil, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.nonSharedData, err = sqlite.NewSqliteEntityStorage[IStorageNonSharedData, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Record Keys
	entityType = reflect.TypeOf((*database.RecordKeyStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"record_uid", "encrypter_uid"}, map[string][]string{"Encrypter": {"encrypter_uid"}}, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.recordKeys, err = sqlite.NewSqliteLinkStorage[IStorageRecordKey, string, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Shared Folder Keys
	entityType = reflect.TypeOf((*database.SharedFolderKeyStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"shared_folder_uid", "encrypter_uid"}, map[string][]string{"Encrypter": {"encrypter_uid"}}, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.sharedFolderKeys, err = sqlite.NewSqliteLinkStorage[IStorageSharedFolderKey, string, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Shared Folder Permissions
	entityType = reflect.TypeOf((*database.SharedFolderPermissionStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"shared_folder_uid", "user_uid"}, map[string][]string{"UserUID": {"user_uid"}}, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.sharedFolderPermissions, err = sqlite.NewSqliteLinkStorage[IStorageSharedFolderPermission, string, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Folders
	entityType = reflect.TypeOf((*database.FolderStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"folder_uid"}, nil, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.folders, err = sqlite.NewSqliteEntityStorage[IStorageFolder, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// Folder Records
	entityType = reflect.TypeOf((*database.FolderRecordStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"folder_uid", "record_uid"}, map[string][]string{"RecordUID": {"record_uid"}}, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.folderRecords, err = sqlite.NewSqliteLinkStorage[IStorageFolderRecord, string, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	// BreachWatch Records
	entityType = reflect.TypeOf((*database.BreachWatchRecordStorage)(nil))
	if tableSchema, err = sqlite.LoadTableSchema(entityType, []string{"record_uid"}, nil, "owner_uid", sqlite.SqlDataType_String); err != nil {
		return
	}
	if _, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{tableSchema}, true); err != nil {
		return
	}
	if sqliteStorage.breachWatchRecords, err = sqlite.NewSqliteEntityStorage[IStorageBreachWatchRecord, string](getter, tableSchema, accountUid); err != nil {
		return
	}

	storage = sqliteStorage
	return
}

type sqliteVaultStorage struct {
	userAccountUid          string
	userSettings            storage.IRecordStorage[IUserSettings]
	records                 storage.IEntityStorage[IStorageRecord, string]
	recordTypes             storage.IEntityStorage[IStorageRecordType, int64]
	sharedFolders           storage.IEntityStorage[IStorageSharedFolder, string]
	teams                   storage.IEntityStorage[IStorageTeam, string]
	userEmails              storage.ILinkStorage[IStorageUserEmail, string, string]
	nonSharedData           storage.IEntityStorage[IStorageNonSharedData, string]
	recordKeys              storage.ILinkStorage[IStorageRecordKey, string, string]
	sharedFolderKeys        storage.ILinkStorage[IStorageSharedFolderKey, string, string]
	sharedFolderPermissions storage.ILinkStorage[IStorageSharedFolderPermission, string, string]
	folders                 storage.IEntityStorage[IStorageFolder, string]
	folderRecords           storage.ILinkStorage[IStorageFolderRecord, string, string]
	breachWatchRecords      storage.IEntityStorage[IStorageBreachWatchRecord, string]
	pendingSharePlugin      IPendingShareStoragePlugin
}

func (svs *sqliteVaultStorage) PersonalScopeUid() string {
	return svs.userAccountUid
}
func (svs *sqliteVaultStorage) UserSettings() storage.IRecordStorage[IUserSettings] {
	return svs.userSettings
}
func (svs *sqliteVaultStorage) Records() storage.IEntityStorage[IStorageRecord, string] {
	return svs.records
}
func (svs *sqliteVaultStorage) RecordTypes() storage.IEntityStorage[IStorageRecordType, int64] {
	return svs.recordTypes
}
func (svs *sqliteVaultStorage) SharedFolders() storage.IEntityStorage[IStorageSharedFolder, string] {
	return svs.sharedFolders
}
func (svs *sqliteVaultStorage) Teams() storage.IEntityStorage[IStorageTeam, string] {
	return svs.teams
}
func (svs *sqliteVaultStorage) UserEmails() storage.ILinkStorage[IStorageUserEmail, string, string] {
	return svs.userEmails
}
func (svs *sqliteVaultStorage) NonSharedData() storage.IEntityStorage[IStorageNonSharedData, string] {
	return svs.nonSharedData
}
func (svs *sqliteVaultStorage) RecordKeys() storage.ILinkStorage[IStorageRecordKey, string, string] {
	return svs.recordKeys
}
func (svs *sqliteVaultStorage) SharedFolderKeys() storage.ILinkStorage[IStorageSharedFolderKey, string, string] {
	return svs.sharedFolderKeys
}
func (svs *sqliteVaultStorage) SharedFolderPermissions() storage.ILinkStorage[IStorageSharedFolderPermission, string, string] {
	return svs.sharedFolderPermissions
}
func (svs *sqliteVaultStorage) Folders() storage.IEntityStorage[IStorageFolder, string] {
	return svs.folders
}
func (svs *sqliteVaultStorage) FolderRecords() storage.ILinkStorage[IStorageFolderRecord, string, string] {
	return svs.folderRecords
}
func (svs *sqliteVaultStorage) BreachWatchRecords() storage.IEntityStorage[IStorageBreachWatchRecord, string] {
	return svs.breachWatchRecords
}

func (svs *sqliteVaultStorage) Clear() {
	var err error
	var logger = api.GetLogger()
	if err = svs.userSettings.Delete(); err != nil {
		logger.Debug("Sqlite Vault storage error", zap.String("Table", "UserSettings"), zap.Error(err))
	}
	// TODO
}

func (svs *sqliteVaultStorage) Close() (err error) {
	return
}

func (svs *sqliteVaultStorage) PendingSharesPlugin() IPendingShareStoragePlugin {
	return svs.pendingSharePlugin
}

func (svs *sqliteVaultStorage) SetPendingSharesPlugin(plugin IPendingShareStoragePlugin) {
	svs.pendingSharePlugin = plugin
}
