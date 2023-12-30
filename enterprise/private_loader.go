package enterprise

import (
	"crypto/ecdh"
	"crypto/rsa"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/auth"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_enterprise"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	"github.com/keeper-security/keeper-sdk-golang/vault"
	"go.uber.org/zap"
)

type enterpriseEntity[T storage.IUid[K], K storage.Key] map[K]T

func (ee enterpriseEntity[T, K]) GetAllEntities(cb func(T) bool) {
	for _, v := range ee {
		if !cb(v) {
			return
		}
	}
}
func (ee enterpriseEntity[T, K]) GetEntity(key K) (t T) {
	if ee != nil {
		t = ee[key]
	}
	return
}

type enterpriseLoader struct {
	keeperAuth        auth.IKeeperAuth
	storage           IEnterpriseStorage
	enterpriseData    *enterpriseData
	continuationToken []byte
	roleKeys          map[int64][]byte
}

func (el *enterpriseLoader) Storage() IEnterpriseStorage {
	return el.storage
}

func (el *enterpriseLoader) EnterpriseData() IEnterpriseData {
	return el.enterpriseData
}

func (el *enterpriseLoader) KeeperAuth() auth.IKeeperAuth {
	return el.keeperAuth
}

func (el *enterpriseLoader) Load() (err error) {
	var logger = api.GetLogger()

	if el.enterpriseData == nil {
		var ei = new(enterpriseInfo)
		var rqKeys = new(proto_enterprise.GetEnterpriseDataKeysRequest)
		var rsKeys = new(proto_enterprise.GetEnterpriseDataKeysResponse)
		if err = el.keeperAuth.ExecuteAuthRest("enterprise/get_enterprise_data_keys", rqKeys, rsKeys); err != nil {
			return
		}
		var data []byte
		data = api.Base64UrlDecode(rsKeys.TreeKey.TreeKey)
		var keyType = rsKeys.TreeKey.KeyTypeId
		switch keyType {
		case proto_enterprise.BackupKeyType_ENCRYPTED_BY_DATA_KEY:
			ei.treeKey, err = api.DecryptAesV1(data, el.keeperAuth.AuthContext().DataKey())
		case proto_enterprise.BackupKeyType_ENCRYPTED_BY_DATA_KEY_GCM:
			ei.treeKey, err = api.DecryptAesV2(data, el.keeperAuth.AuthContext().DataKey())
		case proto_enterprise.BackupKeyType_ENCRYPTED_BY_PUBLIC_KEY:
			ei.treeKey, err = api.DecryptRsa(data, el.keeperAuth.AuthContext().RsaPrivateKey())
		case proto_enterprise.BackupKeyType_ENCRYPTED_BY_PUBLIC_KEY_ECC:
			ei.treeKey, err = api.DecryptEc(data, el.keeperAuth.AuthContext().EcPrivateKey())
		default:
			err = api.NewKeeperError(fmt.Sprintf("Tree key encryption type %s is not supported", keyType.String()))
		}
		if err != nil {
			return
		}
		if len(rsKeys.EnterpriseKeys.RsaEncryptedPrivateKey) > 0 {
			if data, err = api.DecryptAesV2(rsKeys.EnterpriseKeys.RsaEncryptedPrivateKey, ei.treeKey); err == nil {
				ei.rsaPrivateKey, err = api.LoadRsaPrivateKey(data)
			}
		} else {
			var privKey *rsa.PrivateKey
			var pubKey *rsa.PublicKey
			if privKey, pubKey, err = api.GenerateRsaKey(); err == nil {
				data = api.UnloadRsaPrivateKey(privKey)
				if data, err = api.EncryptAesV2(data, ei.treeKey); err == nil {
					var rqSetKey = &proto_enterprise.EnterpriseKeyPairRequest{
						EnterprisePublicKey:           api.UnloadRsaPublicKey(pubKey),
						EncryptedEnterprisePrivateKey: data,
						KeyType:                       proto_enterprise.KeyType_RSA,
					}
					if err = el.keeperAuth.ExecuteAuthRest("enterprise/set_enterprise_key_pair", rqSetKey, nil); err == nil {
						ei.rsaPrivateKey = privKey
					}
				}
			}
		}
		if err != nil {
			logger.Warn("Error loading enterprise RSA key", zap.Error(err))
		}
		if len(rsKeys.EnterpriseKeys.EccEncryptedPrivateKey) > 0 {
			if data, err = api.DecryptAesV2(rsKeys.EnterpriseKeys.EccEncryptedPrivateKey, ei.treeKey); err == nil {
				ei.ecPrivateKey, err = api.LoadEcPrivateKey(data)
			}
		} else {
			var privKey *ecdh.PrivateKey
			var pubKey *ecdh.PublicKey
			if privKey, pubKey, err = api.GenerateEcKey(); err == nil {
				data = api.UnloadEcPrivateKey(privKey)
				if data, err = api.EncryptAesV2(data, ei.treeKey); err == nil {
					var rqSetKey = &proto_enterprise.EnterpriseKeyPairRequest{
						EnterprisePublicKey:           api.UnloadEcPublicKey(pubKey),
						EncryptedEnterprisePrivateKey: data,
						KeyType:                       proto_enterprise.KeyType_ECC,
					}
					if err = el.keeperAuth.ExecuteAuthRest("enterprise/set_enterprise_key_pair", rqSetKey, nil); err == nil {
						ei.ecPrivateKey = privKey
					}
				}
			}
		}
		if err != nil {
			logger.Warn("Error loading enterprise ECC key", zap.Error(err))
			err = nil
		}

		el.enterpriseData = newEnterpriseData(ei)
	}

	if el.enterpriseData.recordTypes == nil {
		el.enterpriseData.recordTypes = make(enterpriseEntity[vault.IRecordType, string])
		var rts = storage.NewInMemoryEntityStorage[vault.IStorageRecordType, int64](func(recordType vault.IStorageRecordType) int64 {
			return recordType.Id()
		})
		if err = vault.LoadRecordTypes(el.KeeperAuth(), rts); err == nil {
			err = rts.GetAll(func(x vault.IStorageRecordType) bool {
				var rti vault.IRecordType
				var er1 error
				if rti, er1 = vault.ParseRecordType(x); er1 == nil {
					el.enterpriseData.recordTypes[rti.Name()] = rti
				} else {
					logger.Debug("parse record type error", zap.Error(er1))
				}
				return true
			})
		}
		if err != nil {
			logger.Warn("enterprise data: load record types", zap.Error(err))
			err = nil
		}
	}

	var treeKey = el.enterpriseData.enterpriseInfo.treeKey
	if el.continuationToken == nil {
		if el.storage != nil {
			if err = el.storage.GetEntities(func(entityType int32, entityData []byte) bool {
				var et = proto_enterprise.EnterpriseDataEntity(entityType)
				if plugin := el.enterpriseData.getEnterprisePlugin(et); plugin != nil {
					var _, _ = plugin.store(entityData, treeKey)
				}
				return true
			}); err != nil {
				return
			}
			if el.continuationToken, err = el.storage.ContinuationToken(); err != nil {
				logger.Warn("Error loading enterprise settings", zap.Error(err))
				el.continuationToken = nil
			}
		}
	}

	for {
		var rqData = &proto_enterprise.EnterpriseDataRequest{}
		if el.continuationToken != nil {
			rqData.ContinuationToken = el.continuationToken
		}
		var rsData = new(proto_enterprise.EnterpriseDataResponse)
		if err = el.keeperAuth.ExecuteAuthRest("enterprise/get_enterprise_data_for_user", rqData, rsData); err != nil {
			return
		}
		if rsData.GetCacheStatus() == proto_enterprise.CacheStatus_CLEAR {
			if el.storage != nil {
				el.storage.Clear()
			}
			for _, x := range el.enterpriseData.getSupportedEntities() {
				if plugin := el.enterpriseData.getEnterprisePlugin(x); plugin != nil {
					plugin.clear()
				}
			}
		}
		if len(el.enterpriseData.enterpriseInfo.enterpriseName) == 0 {
			el.enterpriseData.enterpriseInfo.enterpriseName = rsData.GetGeneralData().GetEnterpriseName()
			el.enterpriseData.enterpriseInfo.isDistributor = rsData.GetGeneralData().GetDistributor()
		}

		for _, ed := range rsData.Data {
			var entityType = ed.GetEntity()
			plugin := el.enterpriseData.getEnterprisePlugin(entityType)
			if plugin == nil {
				continue
			}
			for _, edd := range ed.GetData() {
				var storageKey string
				if ed.GetDelete() {
					if storageKey, err = plugin.delete(edd); err != nil {
						break
					}
					if el.storage != nil {
						err = el.Storage().DeleteEntity(int32(entityType), storageKey, edd)
					}
				} else {
					if storageKey, err = plugin.store(edd, treeKey); err != nil {
						break
					}
					if el.storage != nil {
						err = el.Storage().PutEntity(int32(entityType), storageKey, edd)
					}
				}

				if err != nil {
					break
				}
			}
		}
		if err != nil {
			break
		}
		if el.storage != nil {
			_ = el.Storage().SetContinuationToken(rsData.ContinuationToken)
			err = el.Storage().Flush()
		}
		el.continuationToken = rsData.ContinuationToken
		if !rsData.GetHasMore() {
			break
		}
	}

	var ed = el.enterpriseData
	if ed.rootNode == nil {
		ed.Nodes().GetAllEntities(
			func(node INode) bool {
				if node.ParentId() == 0 {
					if n, ok := node.(INodeEdit); ok {
						n.SetName(ed.enterpriseInfo.enterpriseName)
					}
					ed.rootNode = node
					return false
				}
				return true
			})
	}
	return
}

func (el *enterpriseLoader) LoadRoleKeys(roleKeys map[int64][]byte) (err error) {
	var roleIds []int64
	if el.roleKeys == nil {
		el.roleKeys = make(map[int64][]byte)
	}
	var ok bool
	var roleId int64
	for roleId = range roleKeys {
		if _, ok = el.roleKeys[roleId]; !ok {
			roleIds = append(roleIds, roleId)
		}
	}
	if len(roleIds) > 0 {
		var rq = &proto_enterprise.GetEnterpriseDataKeysRequest{
			RoleId: roleIds,
		}
		var rs = new(proto_enterprise.GetEnterpriseDataKeysResponse)
		if err = el.keeperAuth.ExecuteAuthRest("enterprise/get_enterprise_data_keys", rq, rs); err != nil {
			return
		}
		var data []byte
		var er1 error
		for _, erk := range rs.ReEncryptedRoleKey {
			roleId = erk.RoleId
			if _, ok = el.roleKeys[roleId]; !ok {
				if data, er1 = api.DecryptAesV2(erk.EncryptedRoleKey, el.enterpriseData.enterpriseInfo.treeKey); er1 == nil {
					roleKeys[roleId] = data
				} else {
					api.GetLogger().Debug("decrypt role key 2 error", zap.Error(er1), zap.Int64("roleID", roleId))
				}
			}
		}
		for _, rk := range rs.RoleKey {
			roleId = rk.RoleId
			if _, ok = el.roleKeys[roleId]; !ok {
				data = nil
				err = nil
				var encKey = api.Base64UrlDecode(rk.EncryptedKey)
				switch rk.KeyType {
				case proto_enterprise.EncryptedKeyType_KT_ENCRYPTED_BY_DATA_KEY:
					data, err = api.DecryptAesV1(encKey, el.keeperAuth.AuthContext().DataKey())
				case proto_enterprise.EncryptedKeyType_KT_ENCRYPTED_BY_DATA_KEY_GCM:
					data, err = api.DecryptAesV2(encKey, el.keeperAuth.AuthContext().DataKey())
				case proto_enterprise.EncryptedKeyType_KT_ENCRYPTED_BY_PUBLIC_KEY:
					data, err = api.DecryptRsa(encKey, el.keeperAuth.AuthContext().RsaPrivateKey())
				case proto_enterprise.EncryptedKeyType_KT_ENCRYPTED_BY_PUBLIC_KEY_ECC:
					data, err = api.DecryptEc(encKey, el.keeperAuth.AuthContext().EcPrivateKey())
				}
				if err == nil {
					roleKeys[roleId] = data
				} else {
					api.GetLogger().Debug("decrypt role key error", zap.Error(err), zap.Int64("roleID", roleId))
				}
			}
		}
		err = nil

		roleIds = nil
		for roleId = range roleKeys {
			roleIds = append(roleIds, roleId)
		}
		for _, roleId = range roleIds {
			if data, ok = el.roleKeys[roleId]; ok {
				roleKeys[roleId] = data
			}
		}
	}
	return
}

func NewEnterpriseLoader(keeperAuth auth.IKeeperAuth, storage IEnterpriseStorage) IEnterpriseLoader {
	return &enterpriseLoader{
		keeperAuth: keeperAuth,
		storage:    storage,
	}
}
