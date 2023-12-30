package vault

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/auth"
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_record"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_sync_down"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	"go.uber.org/zap"
)

var (
	_ RebuildTask = new(rebuildTask)
)

func decryptKeeperKey(context auth.IAuthContext, encrypted []byte, keyType proto_record.RecordKeyType) (decrypted []byte, err error) {
	switch keyType {
	case proto_record.RecordKeyType_NO_KEY:
		decrypted = context.DataKey()
	case proto_record.RecordKeyType_ENCRYPTED_BY_DATA_KEY:
		decrypted, err = api.DecryptAesV1(encrypted, context.DataKey())
	case proto_record.RecordKeyType_ENCRYPTED_BY_PUBLIC_KEY:
		decrypted, err = api.DecryptRsa(encrypted, context.RsaPrivateKey())
	case proto_record.RecordKeyType_ENCRYPTED_BY_DATA_KEY_GCM:
		decrypted, err = api.DecryptRsa(encrypted, context.RsaPrivateKey())
	case proto_record.RecordKeyType_ENCRYPTED_BY_PUBLIC_KEY_ECC:
		decrypted, err = api.DecryptEc(encrypted, context.EcPrivateKey())
	default:
		err = fmt.Errorf("key encryption algorithm is not supported: %s", proto_record.RecordKeyType_name[int32(keyType)])
	}
	return
}

type RebuildTask interface {
	IsFullSync() bool
	Records() api.Set[string]
	SharedFolders() api.Set[string]
	AddRecords([]string)
	AddSharedFolders([]string)
}

type rebuildTask struct {
	isFullSync    bool
	records       api.Set[string]
	sharedFolders api.Set[string]
}

func (rt *rebuildTask) IsFullSync() bool {
	return rt.isFullSync
}
func (rt *rebuildTask) Records() api.Set[string] {
	return rt.records
}
func (rt *rebuildTask) SharedFolders() api.Set[string] {
	return rt.sharedFolders
}
func (rt *rebuildTask) AddRecords(recordUIDs []string) {
	if rt.isFullSync {
		if rt.records == nil {
			rt.records = api.NewSet[string]()
		}
		rt.records.Union(recordUIDs)
	}
}
func (rt *rebuildTask) AddSharedFolders(sharedFolderUIDs []string) {
	if rt.isFullSync {
		if rt.sharedFolders == nil {
			rt.sharedFolders = api.NewSet[string]()
		}
		rt.sharedFolders.Union(sharedFolderUIDs)
	}
}

func syncDownRequest(keeperAuth auth.IKeeperAuth, vaultStorage IVaultStorage, syncRecordTypes bool) (task RebuildTask, err error) {
	var logger = api.GetLogger()
	var er1 error

	var emailLookup = make(map[string]string)

	var getAccountUidByEmail = func(email string) (accountUid string) {
		var ook bool
		if accountUid, ook = emailLookup[email]; ook {
			return
		}
		if er1 = vaultStorage.UserEmails().GetLinksForObjects([]string{email}, func(x IStorageUserEmail) bool {
			if x.Email() == email {
				accountUid = x.AccountUid()
			}
			emailLookup[email] = accountUid
			return false
		}); er1 != nil {
			logger.Warn("resolve user accountUid error", zap.String("email", email), zap.Error(er1))
		}
		return
	}

	var userSettings IUserSettings
	if userSettings, err = vaultStorage.UserSettings().Load(); err != nil {
		return
	}
	if userSettings == nil {
		userSettings = &database.UserSettingsStorage{}
	}

	var rqSync = &proto_sync_down.SyncDownRequest{}
	var token = userSettings.ContinuationToken()
	var done = false
	for !done {
		rqSync.ContinuationToken = token
		var rsSync = &proto_sync_down.SyncDownResponse{}
		if err = keeperAuth.ExecuteAuthRest("vault/sync_down", rqSync, rsSync); err != nil {
			return
		}
		done = rsSync.HasMore
		token = rsSync.ContinuationToken
		if rsSync.CacheStatus == proto_sync_down.CacheStatus_CLEAR {
			syncRecordTypes = true
			vaultStorage.Clear()
			logger.Debug("Full Sync")
		}
		if task == nil {
			task = &rebuildTask{
				isFullSync: rsSync.CacheStatus == proto_sync_down.CacheStatus_CLEAR,
			}
		}
		var uids []string
		var links []storage.IUidLink[string, string]
		if len(rsSync.RemovedRecords) > 0 {
			uids = api.SliceSelect(rsSync.RemovedRecords, func(x []byte) string {
				return api.Base64UrlEncode(x)
			})
			task.AddRecords(uids)

			// linked records
			links = api.SliceSelect(uids, func(x string) storage.IUidLink[string, string] {
				return storage.NewUidLink(x, vaultStorage.PersonalScopeUid())
			})
			if err = vaultStorage.RecordKeys().DeleteLinks(links); err != nil {
				return
			}

			// unlink record from user folders
			var folderUIDs = api.NewSet[string]()
			links = nil
			if err = vaultStorage.FolderRecords().GetLinksForObjects(uids, func(record IStorageFolderRecord) bool {
				links = append(links, record)
				folderUIDs.Add(record.SubjectUid())
				return true
			}); err != nil {
				return
			}
			for k := range folderUIDs {
				if k != vaultStorage.PersonalScopeUid() {
					var folder IStorageFolder
					if folder, er1 = vaultStorage.Folders().GetEntity(k); er1 == nil {
						if folder != nil || folder.FolderType() != "user_folder" {
							folderUIDs.Delete(k)
						}
					}
				}
			}

			links = api.SliceWhere(links, func(x storage.IUidLink[string, string]) bool {
				return folderUIDs.Has(x.SubjectUid())
			})
			if err = vaultStorage.FolderRecords().DeleteLinks(links); err != nil {
				return
			}
		}

		if len(rsSync.RemovedTeams) > 0 {
			uids = api.SliceSelect(rsSync.RemovedTeams, func(x []byte) string {
				return api.Base64UrlEncode(x)
			})
			links = nil
			if err = vaultStorage.SharedFolderKeys().GetLinksForObjects(uids, func(x IStorageSharedFolderKey) bool {
				links = append(links, x)
				return true
			}); err != nil {
				return
			}
			task.AddSharedFolders(api.SliceSelect(links, func(x storage.IUidLink[string, string]) string {
				return x.SubjectUid()
			}))
			if err = vaultStorage.SharedFolderKeys().DeleteLinks(links); err != nil {
				return
			}
			if err = vaultStorage.Teams().DeleteUids(uids); err != nil {
				return
			}
		}
		if len(rsSync.RemovedSharedFolders) > 0 {
			uids = api.SliceSelect(rsSync.RemovedSharedFolders, func(x []byte) string {
				return api.Base64UrlEncode(x)
			})
			links = nil
			if err = vaultStorage.RecordKeys().GetLinksForObjects(uids, func(x IStorageRecordKey) bool {
				links = append(links, x)
				return true
			}); err != nil {
				return
			}
			task.AddSharedFolders(uids)
			task.AddRecords(api.SliceSelect(links, func(x storage.IUidLink[string, string]) string {
				return x.SubjectUid()
			}))
			if err = vaultStorage.SharedFolderKeys().DeleteLinks(api.SliceSelect(uids, func(x string) storage.IUidLink[string, string] {
				return storage.NewUidLink(x, vaultStorage.PersonalScopeUid())
			})); err != nil {
				return
			}
			// delete subfolders
			var sfs = api.NewSet[string]()
			sfs.Union(uids)
			var sfToRemove []string
			if err = vaultStorage.Folders().GetAll(func(x IStorageFolder) bool {
				if sfs.Has(x.SharedFolderUid()) {
					sfToRemove = append(sfToRemove, x.FolderUid())
				}
				return true
			}); err != nil {
				return
			}
			if err = vaultStorage.Folders().DeleteUids(sfToRemove); err != nil {
				return
			}
			if err = vaultStorage.FolderRecords().DeleteLinksForSubjects(sfToRemove); err != nil {
				return
			}
		}
		if len(rsSync.RemovedRecordLinks) > 0 {
			links = api.SliceSelect(rsSync.RemovedRecordLinks, func(x *proto_sync_down.RecordLink) storage.IUidLink[string, string] {
				return storage.NewUidLink(api.Base64UrlEncode(x.ChildRecordUid), api.Base64UrlEncode(x.ParentRecordUid))
			})
			task.AddRecords(api.SliceSelect(links, func(x storage.IUidLink[string, string]) string {
				return x.SubjectUid()
			}))
			if err = vaultStorage.RecordKeys().DeleteLinks(links); err != nil {
				return
			}
		}
		if len(rsSync.RemovedUserFolders) > 0 {
			uids = api.SliceSelect(rsSync.RemovedUserFolders, func(x []byte) string {
				return api.Base64UrlEncode(x)
			})
			if err = vaultStorage.FolderRecords().DeleteLinksForSubjects(uids); err != nil {
				return
			}
			if err = vaultStorage.Folders().DeleteUids(uids); err != nil {
				return
			}
		}
		if len(rsSync.RemovedSharedFolderFolders) > 0 {
			uids = api.SliceSelect(rsSync.RemovedSharedFolderFolders, func(x *proto_sync_down.SharedFolderFolder) string {
				if len(x.FolderUid) > 0 {
					return api.Base64UrlEncode(x.FolderUid)
				}
				return api.Base64UrlEncode(x.SharedFolderUid)
			})
			if err = vaultStorage.FolderRecords().DeleteLinksForSubjects(uids); err != nil {
				return
			}
			if err = vaultStorage.Folders().DeleteUids(uids); err != nil {
				return
			}
		}
		if len(rsSync.RemovedUserFolderSharedFolders) > 0 {
			uids = api.SliceSelect(rsSync.RemovedUserFolderSharedFolders, func(x *proto_sync_down.UserFolderSharedFolder) string {
				return api.Base64UrlEncode(x.SharedFolderUid)
			})
			if err = vaultStorage.FolderRecords().DeleteLinksForSubjects(uids); err != nil {
				return
			}
			if err = vaultStorage.Folders().DeleteUids(uids); err != nil {
				return
			}
		}
		if len(rsSync.RemovedUserFolderRecords) > 0 {
			links = api.SliceSelect(rsSync.RemovedUserFolderRecords, func(x *proto_sync_down.UserFolderRecord) storage.IUidLink[string, string] {
				var uid string
				if len(x.FolderUid) > 0 {
					uid = api.Base64UrlEncode(x.FolderUid)
				} else {
					uid = vaultStorage.PersonalScopeUid()
				}
				return storage.NewUidLink(uid, api.Base64UrlEncode(x.RecordUid))
			})
			if err = vaultStorage.FolderRecords().DeleteLinks(links); err != nil {
				return
			}
		}
		if len(rsSync.RemovedSharedFolderFolderRecords) > 0 {
			links = api.SliceSelect(rsSync.RemovedSharedFolderFolderRecords, func(x *proto_sync_down.SharedFolderFolderRecord) storage.IUidLink[string, string] {
				var uid string
				if len(x.FolderUid) > 0 {
					uid = api.Base64UrlEncode(x.FolderUid)
				} else {
					uid = vaultStorage.PersonalScopeUid()
				}
				return storage.NewUidLink(uid, api.Base64UrlEncode(x.RecordUid))
			})
			if err = vaultStorage.FolderRecords().DeleteLinks(links); err != nil {
				return
			}
		}
		if len(rsSync.RecordMetaData) > 0 {
			var recordKeys []IStorageRecordKey
			api.SliceForeach(rsSync.RecordMetaData, func(x *proto_sync_down.RecordMetaData) {
				var uid = api.Base64UrlEncode(x.RecordUid)
				var ownerUid string
				if len(x.OwnerAccountUid) > 0 {
					ownerUid = api.Base64UrlEncode(x.OwnerAccountUid)
				} else {
					ownerUid = vaultStorage.PersonalScopeUid()
				}
				var key []byte
				if key, er1 = decryptKeeperKey(keeperAuth.AuthContext(), x.RecordKey, x.RecordKeyType); er1 == nil {
					key, er1 = api.EncryptAesV2(key, keeperAuth.AuthContext().ClientKey())
				}
				if er1 == nil {
					var rks = &database.RecordKeyStorage{
						RecordUid_:       uid,
						EncrypterUid_:    vaultStorage.PersonalScopeUid(),
						KeyType_:         int32(StorageKeyType_UserClientKey_AES_GCM),
						RecordKey_:       key,
						CanShare_:        x.CanShare,
						CanEdit_:         x.CanEdit,
						ExpirationTime_:  x.Expiration,
						Owner_:           x.Owner,
						OwnerAccountUid_: ownerUid,
					}
					recordKeys = append(recordKeys, rks)
				} else {
					logger.Warn("record key decrypt error", zap.String("record_uid", uid),
						zap.String("encryptor", vaultStorage.PersonalScopeUid()), zap.Error(er1))
				}
			})
			if err = vaultStorage.RecordKeys().PutLinks(recordKeys); err != nil {
				return
			}
			task.AddRecords(api.SliceSelect(recordKeys, func(x IStorageRecordKey) string {
				return x.RecordUid()
			}))
		}
		if len(rsSync.RecordLinks) > 0 {
			var recordKeys = api.SliceSelect(rsSync.RecordLinks, func(x *proto_sync_down.RecordLink) IStorageRecordKey {
				return &database.RecordKeyStorage{
					RecordUid_:    api.Base64UrlEncode(x.ChildRecordUid),
					EncrypterUid_: api.Base64UrlEncode(x.ParentRecordUid),
					KeyType_:      int32(StorageKeyType_RecordKey_AES_GCM),
					RecordKey_:    x.RecordKey,
					CanShare_:     false,
					CanEdit_:      false,
				}
			})
			if err = vaultStorage.RecordKeys().PutLinks(recordKeys); err != nil {
				return
			}
			task.AddRecords(api.SliceSelect(recordKeys, func(x IStorageRecordKey) string {
				return x.RecordUid()
			}))
		}
		if len(rsSync.Records) > 0 {
			var records = api.SliceSelect(rsSync.Records, func(x *proto_sync_down.Record) IStorageRecord {
				var udata = x.Udata
				if x.FileSize > 0 || x.ThumbnailSize > 0 {
					var uu = make(map[string]interface{})
					if len(udata) > 0 {
						_ = json.Unmarshal([]byte(udata), &uu)
					}
					if x.FileSize > 0 {
						uu["file_size"] = x.FileSize
					}
					if x.ThumbnailSize > 0 {
						uu["thumbnail_size"] = x.ThumbnailSize
					}
					var data []byte
					if data, er1 = json.Marshal(uu); er1 == nil {
						udata = string(data)
					}
				}
				var r = &database.RecordStorage{
					RecordUid_:    api.Base64UrlEncode(x.RecordUid),
					Revision_:     x.Revision,
					Version_:      x.Version,
					ModifiedTime_: x.ClientModifiedTime,
					Data_:         x.Data,
					Extra_:        x.Extra,
					UData_:        udata,
					Shared_:       x.Shared,
				}
				return r
			})
			if err = vaultStorage.Records().PutEntities(records); err != nil {
				return
			}
			task.AddRecords(api.SliceSelect(records, func(x IStorageRecord) string {
				return x.RecordUid()
			}))
		}
		if len(rsSync.NonSharedData) > 0 {
			var nsds = api.SliceSelect(rsSync.NonSharedData, func(x *proto_sync_down.NonSharedData) IStorageNonSharedData {
				return &database.NonSharedDataStorage{
					RecordUid_: api.Base64UrlEncode(x.RecordUid),
					Data_:      x.Data,
				}
			})
			if err = vaultStorage.NonSharedData().PutEntities(nsds); err != nil {
				return
			}
		}
		if len(rsSync.RemovedUsers) > 0 {
			uids = api.SliceSelect(rsSync.RemovedUsers, func(x []byte) string {
				return api.Base64UrlEncode(x)
			})
			if err = vaultStorage.UserEmails().DeleteLinksForSubjects(uids); err != nil {
				return
			}
		}
		if len(rsSync.Users) > 0 {
			var userEmails = api.SliceSelect(rsSync.Users, func(x *proto_sync_down.User) IStorageUserEmail {
				return &database.UserEmailStorage{
					AccountUid_: api.Base64UrlEncode(x.AccountUid),
					Email_:      x.Username,
				}
			})
			if err = vaultStorage.UserEmails().PutLinks(userEmails); err != nil {
				return
			}
		}
		if len(rsSync.Teams) > 0 {
			links = nil
			for _, t := range rsSync.Teams {
				var teamUid = api.Base64UrlEncode(t.TeamUid)
				for _, sf := range t.RemovedSharedFolders {
					links = append(links, storage.NewUidLink(api.Base64UrlEncode(sf), teamUid))
				}
			}
			if len(links) > 0 {
				task.AddSharedFolders(api.SliceSelect(links, func(x storage.IUidLink[string, string]) string {
					return x.SubjectUid()
				}))
				if err = vaultStorage.SharedFolderKeys().DeleteLinks(links); err != nil {
					return
				}
			}
			var teams []IStorageTeam
			var sfKeys []IStorageSharedFolderKey
			api.SliceForeach(rsSync.Teams, func(x *proto_sync_down.Team) {
				var teamUid = api.Base64UrlEncode(x.TeamUid)
				var teamKey []byte
				var encryptedKey []byte
				var teamPrivateKey *rsa.PrivateKey
				if teamKey, er1 = decryptKeeperKey(keeperAuth.AuthContext(), x.TeamKey, x.TeamKeyType); er1 == nil {
					if encryptedKey, er1 = api.EncryptAesV2(teamKey, keeperAuth.AuthContext().ClientKey()); er1 == nil {
						var data []byte
						if data, er1 = api.DecryptAesV1(x.TeamPrivateKey, teamKey); er1 == nil {
							teamPrivateKey, er1 = api.LoadRsaPrivateKey(data)
						}
					}
					if er1 != nil {
						logger.Warn("team private key decrypt error", zap.String("team_uid", teamUid),
							zap.Int32("key_type", int32(x.TeamKeyType)),
							zap.String("encryptor", vaultStorage.PersonalScopeUid()), zap.Error(er1))
						er1 = nil
					}
				}
				if er1 == nil {
					var t = &database.TeamStorage{
						TeamUid_:        teamUid,
						Name_:           x.Name,
						TeamKey_:        encryptedKey,
						KeyType_:        int32(StorageKeyType_UserClientKey_AES_GCM),
						TeamPrivateKey_: x.TeamPrivateKey,
						RestrictEdit_:   x.RestrictEdit,
						RestrictShare_:  x.RestrictShare,
						RestrictView_:   x.RestrictView,
					}
					teams = append(teams, t)
					api.SliceForeach(x.SharedFolderKeys, func(k *proto_sync_down.SharedFolderKey) {
						var sharedFolderUid = api.Base64UrlEncode(k.SharedFolderUid)
						switch k.KeyType {
						case proto_record.RecordKeyType_ENCRYPTED_BY_DATA_KEY:
							encryptedKey, er1 = api.DecryptAesV1(k.SharedFolderKey, teamKey)
						case proto_record.RecordKeyType_ENCRYPTED_BY_PUBLIC_KEY:
							encryptedKey, er1 = api.DecryptRsa(k.SharedFolderKey, teamPrivateKey)
						default:
							er1 = fmt.Errorf("unsupported shared folder \"%s\" key team \"%s\" encryption type", sharedFolderUid, teamUid)
						}
						if er1 == nil {
							encryptedKey, er1 = api.EncryptAesV2(encryptedKey, teamKey)
						}
						if er1 == nil {
							var sfKey = &database.SharedFolderKeyStorage{
								SharedFolderUid_: sharedFolderUid,
								EncrypterUid_:    teamUid,
								KeyType_:         int32(StorageKeyType_TeamKey_AES_GCM),
								SharedFolderKey_: encryptedKey,
							}
							sfKeys = append(sfKeys, sfKey)
						} else {
							logger.Warn("shared folder key decrypt error",
								zap.String("shared_folder_uid", sharedFolderUid),
								zap.Int32("key_type", int32(k.KeyType)),
								zap.String("encryptor", teamUid), zap.Error(er1))
						}
					})
				} else {
					logger.Warn("team key decrypt error", zap.String("team_uid", teamUid),
						zap.String("encryptor", vaultStorage.PersonalScopeUid()), zap.Error(er1))
				}
			})
			if err = vaultStorage.Teams().PutEntities(teams); err != nil {
				return
			}
		}
		if len(rsSync.SharedFolders) > 0 {
			uids = nil
			api.SliceForeach(rsSync.SharedFolders, func(x *proto_sync_down.SharedFolder) {
				if x.CacheStatus == proto_sync_down.CacheStatus_CLEAR {
					uids = append(uids, api.Base64UrlEncode(x.SharedFolderUid))
				}
			})
			if len(uids) > 0 {
				_ = vaultStorage.SharedFolderKeys().DeleteLinksForSubjects(uids)
				_ = vaultStorage.SharedFolderPermissions().DeleteLinksForSubjects(uids)
			}
			var sharedFolders []IStorageSharedFolder
			var sharedFolderKeys []IStorageSharedFolderKey
			api.SliceForeach(rsSync.SharedFolders, func(x *proto_sync_down.SharedFolder) {
				var sharedFolderUid = api.Base64UrlEncode(x.SharedFolderUid)
				var sf = &database.SharedFolderStorage{
					SharedFolderUid_:      sharedFolderUid,
					Revision_:             x.Revision,
					Name_:                 x.Name,
					Data_:                 x.Data,
					DefaultManageRecords_: x.DefaultManageRecords,
					DefaultManageUsers_:   x.DefaultManageUsers,
					DefaultCanEdit_:       x.DefaultCanEdit,
					DefaultCanShare_:      x.DefaultCanReshare,
				}
				if len(x.OwnerAccountUid) > 0 {
					sf.OwnerAccountUid_ = api.Base64UrlEncode(x.OwnerAccountUid)
				}
				sharedFolders = append(sharedFolders, sf)
				if len(x.SharedFolderKey) > 0 {
					var sharedFolderKey []byte
					var encryptedKey []byte
					if sharedFolderKey, er1 = decryptKeeperKey(keeperAuth.AuthContext(), x.SharedFolderKey, x.KeyType); er1 == nil {
						encryptedKey, er1 = api.EncryptAesV2(sharedFolderKey, keeperAuth.AuthContext().ClientKey())
					}
					if er1 == nil {
						var sfk = &database.SharedFolderKeyStorage{
							SharedFolderUid_: sharedFolderUid,
							EncrypterUid_:    vaultStorage.PersonalScopeUid(),
							KeyType_:         int32(StorageKeyType_UserClientKey_AES_GCM),
							SharedFolderKey_: encryptedKey,
						}
						sharedFolderKeys = append(sharedFolderKeys, sfk)
					}
				}
			})
			task.AddSharedFolders(api.SliceSelect(sharedFolders, func(x IStorageSharedFolder) string {
				return x.SharedFolderUid()
			}))
			if err = vaultStorage.SharedFolders().PutEntities(sharedFolders); err != nil {
				return
			}
			if len(sharedFolderKeys) > 0 {
				if err = vaultStorage.SharedFolderKeys().PutLinks(sharedFolderKeys); err != nil {
					return
				}
			}
		}
		if len(rsSync.RemovedSharedFolderUsers) > 0 {
			links = nil
			api.SliceForeach(rsSync.RemovedSharedFolderUsers, func(x *proto_sync_down.SharedFolderUser) {
				var sharedFolderUid = api.Base64UrlEncode(x.SharedFolderUid)
				var accountUid string
				if len(x.AccountUid) > 0 {
					accountUid = api.Base64UrlEncode(x.AccountUid)
				} else if len(x.Username) > 0 {
					accountUid = getAccountUidByEmail(x.Username)
				}
				if len(accountUid) > 0 {
					links = append(links, storage.NewUidLink(sharedFolderUid, accountUid))
				}
			})
			if len(links) > 0 {
				if err = vaultStorage.SharedFolderPermissions().DeleteLinks(links); err != nil {
					return
				}
			}
		}
		if len(rsSync.SharedFolderUsers) > 0 {
			var users []IStorageSharedFolderPermission
			api.SliceForeach(rsSync.SharedFolderUsers, func(x *proto_sync_down.SharedFolderUser) {
				var accountUid string
				if len(x.AccountUid) > 0 {
					accountUid = api.Base64UrlEncode(x.AccountUid)
				} else if len(x.Username) > 0 {
					accountUid = getAccountUidByEmail(x.Username)
				}
				if len(accountUid) > 0 {
					var sfp = &database.SharedFolderPermissionStorage{
						SharedFolderUid_: api.Base64UrlEncode(x.SharedFolderUid),
						UserUid_:         accountUid,
						UserType_:        int32(SharedFolderUserType_User),
						ManageRecords_:   x.ManageRecords,
						ManageUsers_:     x.ManageUsers,
						ExpirationTime_:  x.Expiration,
					}
					users = append(users, sfp)
				}
			})
			if len(users) > 0 {
				if err = vaultStorage.SharedFolderPermissions().PutLinks(users); err != nil {
					return
				}
			}
		}
		if len(rsSync.RemovedSharedFolderTeams) > 0 {
			links = api.SliceSelect(rsSync.RemovedSharedFolderTeams, func(x *proto_sync_down.SharedFolderTeam) storage.IUidLink[string, string] {
				return storage.NewUidLink(api.Base64UrlEncode(x.SharedFolderUid), api.Base64UrlEncode(x.TeamUid))
			})
			if err = vaultStorage.SharedFolderPermissions().DeleteLinks(links); err != nil {
				return
			}
		}
		if len(rsSync.SharedFolderTeams) > 0 {
			var teams []IStorageSharedFolderPermission
			api.SliceForeach(rsSync.SharedFolderTeams, func(x *proto_sync_down.SharedFolderTeam) {
				var teamUid = api.Base64UrlEncode(x.TeamUid)
				var sfp = &database.SharedFolderPermissionStorage{
					SharedFolderUid_: api.Base64UrlEncode(x.SharedFolderUid),
					UserUid_:         teamUid,
					UserType_:        int32(SharedFolderUserType_Team),
					ManageRecords_:   x.ManageRecords,
					ManageUsers_:     x.ManageUsers,
					ExpirationTime_:  x.Expiration,
				}
				teams = append(teams, sfp)
			})
			if err = vaultStorage.SharedFolderPermissions().PutLinks(teams); err != nil {
				return
			}
		}

		if len(rsSync.RemovedSharedFolderRecords) > 0 {
			links = api.SliceSelect(rsSync.RemovedSharedFolderRecords, func(x *proto_sync_down.SharedFolderRecord) storage.IUidLink[string, string] {
				return storage.NewUidLink(api.Base64UrlEncode(x.RecordUid), api.Base64UrlEncode(x.SharedFolderUid))
			})
			if err = vaultStorage.RecordKeys().DeleteLinks(links); err != nil {
				return
			}
		}
		if len(rsSync.SharedFolderRecords) > 0 {
			var sfRecordKeys []IStorageRecordKey
			api.SliceForeach(rsSync.SharedFolderRecords, func(x *proto_sync_down.SharedFolderRecord) {
				var rk = &database.RecordKeyStorage{
					RecordUid_:      api.Base64UrlEncode(x.RecordUid),
					EncrypterUid_:   api.Base64UrlEncode(x.SharedFolderUid),
					KeyType_:        int32(StorageKeyType_SharedFolderKey_AES_Any),
					RecordKey_:      x.RecordKey,
					CanShare_:       x.CanShare,
					CanEdit_:        x.CanEdit,
					ExpirationTime_: x.Expiration,
					Owner_:          x.Owner,
				}
				var ownerId string
				if len(x.OwnerAccountUid) > 0 {
					ownerId = api.Base64UrlEncode(x.OwnerAccountUid)
				} else if x.Owner {
					ownerId = keeperAuth.AuthContext().AccountUid()
				}
				rk.OwnerAccountUid_ = ownerId
				sfRecordKeys = append(sfRecordKeys, rk)
			})
			if err = vaultStorage.RecordKeys().PutLinks(sfRecordKeys); err != nil {
				return
			}
			task.AddRecords(api.SliceSelect(sfRecordKeys, func(x IStorageRecordKey) string {
				return x.RecordUid()
			}))
		}

		if len(rsSync.UserFolders) > 0 {
			var userFolders []IStorageFolder
			api.SliceForeach(rsSync.UserFolders, func(x *proto_sync_down.UserFolder) {
				var folderKey []byte
				var encryptedKey []byte
				if folderKey, er1 = decryptKeeperKey(keeperAuth.AuthContext(), x.UserFolderKey, x.KeyType); er1 == nil {
					encryptedKey, er1 = api.EncryptAesV2(folderKey, keeperAuth.AuthContext().ClientKey())
				}
				if er1 == nil {
					var f = &database.FolderStorage{
						FolderUid_:  api.Base64UrlEncode(x.FolderUid),
						ParentUid_:  api.Base64UrlEncode(x.ParentUid),
						FolderType_: "user_folder",
						FolderKey_:  encryptedKey,
						KeyType_:    int32(StorageKeyType_UserClientKey_AES_GCM),
						Revision_:   x.Revision,
						Data_:       x.Data,
					}
					userFolders = append(userFolders, f)
				}
			})
			if err = vaultStorage.Folders().PutEntities(userFolders); err != nil {
				return
			}
		}
		if len(rsSync.UserFolderSharedFolders) > 0 {
			var ufsfs = api.SliceSelect(rsSync.UserFolderSharedFolders, func(x *proto_sync_down.UserFolderSharedFolder) IStorageFolder {
				return &database.FolderStorage{
					FolderUid_:       api.Base64UrlEncode(x.SharedFolderUid),
					ParentUid_:       api.Base64UrlEncode(x.FolderUid),
					FolderType_:      "shared_folder",
					SharedFolderUid_: api.Base64UrlEncode(x.SharedFolderUid),
					Revision_:        x.Revision,
				}
			})
			if err = vaultStorage.Folders().PutEntities(ufsfs); err != nil {
				return
			}
		}
		if len(rsSync.SharedFolderFolders) > 0 {
			var sffs = api.SliceSelect(rsSync.SharedFolderFolders, func(x *proto_sync_down.SharedFolderFolder) IStorageFolder {
				return &database.FolderStorage{
					FolderUid_:       api.Base64UrlEncode(x.FolderUid),
					ParentUid_:       api.Base64UrlEncode(x.ParentUid),
					FolderType_:      "shared_folder_folder",
					SharedFolderUid_: api.Base64UrlEncode(x.SharedFolderUid),
					FolderKey_:       x.SharedFolderFolderKey,
					KeyType_:         int32(StorageKeyType_SharedFolderKey_AES_Any),
					Revision_:        x.Revision,
					Data_:            x.Data,
				}
			})
			if err = vaultStorage.Folders().PutEntities(sffs); err != nil {
				return
			}
		}

		if len(rsSync.UserFolderRecords) > 0 {
			var folderRecords = api.SliceSelect(rsSync.UserFolderRecords, func(x *proto_sync_down.UserFolderRecord) IStorageFolderRecord {
				var folderUid string
				if len(x.FolderUid) > 0 {
					folderUid = api.Base64UrlEncode(x.FolderUid)
				} else {
					folderUid = vaultStorage.PersonalScopeUid()
				}
				return &database.FolderRecordStorage{
					FolderUid_: folderUid,
					RecordUid_: api.Base64UrlEncode(x.RecordUid),
				}
			})
			if err = vaultStorage.FolderRecords().PutLinks(folderRecords); err != nil {
				return
			}
		}
		if len(rsSync.SharedFolderFolderRecords) > 0 {
			var folderRecords = api.SliceSelect(rsSync.SharedFolderFolderRecords, func(x *proto_sync_down.SharedFolderFolderRecord) IStorageFolderRecord {
				var folderUid string
				if len(x.FolderUid) > 0 {
					folderUid = api.Base64UrlEncode(x.FolderUid)
				} else {
					folderUid = api.Base64UrlEncode(x.SharedFolderUid)
				}
				return &database.FolderRecordStorage{
					FolderUid_: folderUid,
					RecordUid_: api.Base64UrlEncode(x.RecordUid),
				}
			})
			if err = vaultStorage.FolderRecords().PutLinks(folderRecords); err != nil {
				return
			}
		}

		if len(rsSync.SharingChanges) > 0 {
			var records []IStorageRecord
			api.SliceForeach(rsSync.SharingChanges, func(x *proto_sync_down.SharingChange) {
				var record IStorageRecord
				if record, er1 = vaultStorage.Records().GetEntity(api.Base64UrlEncode(x.RecordUid)); er1 == nil {
					if record != nil {
						if record.Shared() != x.Shared {
							record.SetShared(x.Shared)
							records = append(records, record)
						}
					}
				}
			})
			if len(records) > 0 {
				if err = vaultStorage.Records().PutEntities(records); err != nil {
					return
				}
			}
		}

		if len(rsSync.BreachWatchRecords) > 0 {
			var bwrs = api.SliceSelect(rsSync.BreachWatchRecords, func(x *proto_sync_down.BreachWatchRecord) IStorageBreachWatchRecord {
				return &database.BreachWatchRecordStorage{
					RecordUid_: api.Base64UrlEncode(x.RecordUid),
					Data_:      x.Data,
					Type_:      int32(x.Type),
					Revision_:  x.Revision,
				}
			})
			if er1 = vaultStorage.BreachWatchRecords().PutEntities(bwrs); err != nil {
				logger.Warn("breachwatch record store error", zap.Error(er1))
			}
		}
		//if len(rsSync.BreachWatchSecurityData) > 0 {
		//	var bwsds = api.SliceSelect(rsSync.BreachWatchSecurityData, func(x *proto_sync_down.BreachWatchSecurityData) IStorageB {
		//
		//	})
		//}

		if len(rsSync.ShareInvitations) > 0 {
			var psp = vaultStorage.PendingSharesPlugin()
			if psp != nil {
				psp.AddPendingShares(api.SliceSelect(rsSync.ShareInvitations, func(x *proto_sync_down.ShareInvitation) string {
					return x.Username
				}))
			}
		}

		if rsSync.Profile.Revision > 0 {
			userSettings.SetProfileName(rsSync.Profile.ProfileName)
			if len(rsSync.Profile.Data) > 0 {
				var data []byte
				if data, er1 = api.DecryptAesV1(rsSync.Profile.Data, keeperAuth.AuthContext().DataKey()); er1 == nil {
					data, er1 = api.EncryptAesV2(data, keeperAuth.AuthContext().DataKey())
				}
				if er1 == nil {
					userSettings.SetProfileData(data)
				} else {
					logger.Warn("profile data decrypt error", zap.Error(er1))
				}
			}
		}
		if rsSync.ProfilePic.Revision > 0 {
			userSettings.SetProfileUrl(rsSync.ProfilePic.Url)
		}
		userSettings.SetContinuationToken(token)
	}
	err = vaultStorage.UserSettings().Store(userSettings)
	if err == nil {
		if syncRecordTypes {
			err = LoadRecordTypes(keeperAuth, vaultStorage.RecordTypes())
		}
	}
	return
}
