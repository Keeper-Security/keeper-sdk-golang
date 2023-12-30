package enterprise

import (
	"encoding/json"
	"errors"
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_enterprise"
	"github.com/keeper-security/keeper-sdk-golang/sqlite"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"reflect"
)

func NewSqliteEnterpriseStorage(getConnection func() *sqlx.DB, enterpriseId int64) (storage IEnterpriseStorage, err error) {
	var db = getConnection()

	const ownerColumnName = "enterprise_id"
	var settingsType = reflect.TypeOf((*database.EnterpriseSettings)(nil))
	var settingsSchema sqlite.ITableSchema
	settingsSchema, err = sqlite.LoadTableSchema(settingsType, nil, nil, ownerColumnName, sqlite.SqlDataType_Integer)
	if err != nil {
		return
	}

	var dataType = reflect.TypeOf((*database.EnterpriseEntityData)(nil))
	var dataSchema sqlite.ITableSchema
	var indexes = make(map[string][]string)
	indexes["ObjectKey"] = []string{"key"}
	dataSchema, err = sqlite.LoadTableSchema(dataType, []string{"type", "key"}, indexes, ownerColumnName, sqlite.SqlDataType_Integer)
	if err != nil {
		return
	}

	var queries []string
	if queries, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{settingsSchema, dataSchema}, true); err != nil {
		return
	}
	if len(queries) > 0 {
		err = errors.New("failed to modify database schema")
		return
	}

	var es = &enterpriseStorage{}
	es.settingStorage, err = sqlite.NewSqliteRecordStorage[*database.EnterpriseSettings](getConnection, settingsSchema, enterpriseId)
	if err != nil {
		return
	}
	es.dataStorage, err = sqlite.NewSqliteLinkStorage[*database.EnterpriseEntityData, int64, string](getConnection, dataSchema, enterpriseId)
	if err != nil {
		return
	}
	storage = es
	return
}

type enterpriseStorage struct {
	settingStorage storage.IRecordStorage[*database.EnterpriseSettings]
	dataStorage    storage.ILinkStorage[*database.EnterpriseEntityData, int64, string]
	putCache       []*database.EnterpriseEntityData
	deleteCache    []storage.IUidLink[int64, string]
}

func (es *enterpriseStorage) ContinuationToken() (token []byte, err error) {
	var settings *database.EnterpriseSettings
	if settings, err = es.settingStorage.Load(); err == nil {
		if settings != nil {
			token = settings.ContinuationToken
		}
	}
	return
}

func (es *enterpriseStorage) SetContinuationToken(token []byte) (err error) {
	var settings *database.EnterpriseSettings
	if settings, err = es.settingStorage.Load(); err == nil {
		if settings == nil {
			settings = &database.EnterpriseSettings{}
		}
		settings.ContinuationToken = token
		err = es.settingStorage.Store(settings)
	}
	return
}

func (es *enterpriseStorage) EnterpriseIds() (ids []int64, err error) {
	var settings *database.EnterpriseSettings
	if settings, err = es.settingStorage.Load(); err == nil {
		if settings != nil {
			var jsonIds = settings.EnterpriseIds
			if len(jsonIds) > 0 {
				if er1 := json.Unmarshal([]byte(jsonIds), &ids); er1 != nil {
					api.GetLogger().Debug("error parsing json", zap.Error(er1))
				}
			}
			settings.EnterpriseIds = ""
			err = es.settingStorage.Store(settings)
		}
	}
	return
}
func (es *enterpriseStorage) SetEnterpriseIds(ids []int64) (err error) {
	var settings *database.EnterpriseSettings
	if settings, err = es.settingStorage.Load(); err == nil {
		if settings == nil {
			settings = new(database.EnterpriseSettings)
		}
		var jsonIds []int64
		if len(settings.EnterpriseIds) > 0 {
			_ = json.Unmarshal([]byte(settings.EnterpriseIds), &jsonIds)
		}
		jsonIds = append(jsonIds, ids...)
		var data []byte
		if data, err = json.Marshal(jsonIds); err == nil {
			settings.EnterpriseIds = string(data)
			err = es.settingStorage.Store(settings)
		}
	}
	return
}

func (es *enterpriseStorage) GetEntities(cb func(int32, []byte) bool) (err error) {
	err = es.dataStorage.GetAll(func(data *database.EnterpriseEntityData) bool {
		return cb(int32(data.Type), data.Data)
	})
	return
}

func (es *enterpriseStorage) Flush() (err error) {
	if len(es.deleteCache) > 0 {
		err = es.dataStorage.DeleteLinks(es.deleteCache)
		es.deleteCache = nil
	}
	if len(es.putCache) > 0 {
		err = es.dataStorage.PutLinks(es.putCache)
		es.putCache = nil
	}
	return
}

func (es *enterpriseStorage) transformData(rq *dataTask) (rs *dataTask, err error) {
	if rq != nil {
		if rq.dataType == int32(proto_enterprise.EnterpriseDataEntity_QUEUED_TEAMS) {
			var qtu = new(proto_enterprise.QueuedTeamUser)
			if err = proto.Unmarshal(rq.data, qtu); err != nil {
				return
			}
			var origData *database.EnterpriseEntityData
			if origData, err = es.dataStorage.GetLink(int64(rq.dataType), rq.dataKey); err != nil {
				return
			}
			if origData != nil {
				var origQtu = new(proto_enterprise.QueuedTeamUser)
				if err = proto.Unmarshal(rq.data, origQtu); err != nil {
					return
				}
				var origUsers = make(map[int64]bool)
				for _, k := range origQtu.Users {
					origUsers[k] = true
				}
				for _, k := range qtu.Users {
					if rq.isDelete {
						delete(origUsers, k)
					} else {
						origUsers[k] = true
					}
				}
				qtu.Users = nil
				if len(origUsers) > 0 {
					for k := range origUsers {
						qtu.Users = append(qtu.Users, k)
					}
				}
				var data []byte
				if data, err = proto.Marshal(qtu); err != nil {
					return
				}
				rs = &dataTask{
					isDelete: len(origUsers) == 0,
					dataType: rq.dataType,
					dataKey:  rq.dataKey,
					data:     data,
				}
				return
			} else {
				if rq.isDelete {
					return
				}
			}
		}
	}
	rs = rq
	return
}

func (es *enterpriseStorage) scheduleTask(task *dataTask) (err error) {
	if task != nil {
		if !task.isDelete {
			es.putCache = append(es.putCache, &database.EnterpriseEntityData{
				Type: int64(task.dataType),
				Key:  task.dataKey,
				Data: task.data,
			})
			if len(es.putCache) >= 1000 {
				err = es.Flush()
			}
		} else {
			es.deleteCache = append(es.deleteCache, storage.NewUidLink(int64(task.dataType), task.dataKey))
			if len(es.deleteCache) >= 1000 {
				err = es.Flush()
			}
		}
	}
	return
}

func (es *enterpriseStorage) PutEntity(dataType int32, dataKey string, data []byte) (err error) {
	var preTask = &dataTask{
		isDelete: false,
		dataType: dataType,
		dataKey:  dataKey,
		data:     data,
	}
	var postTask *dataTask
	if postTask, err = es.transformData(preTask); err == nil {
		err = es.scheduleTask(postTask)
	}
	return
}

func (es *enterpriseStorage) DeleteEntity(dataType int32, dataKey string, data []byte) (err error) {
	var preTask = &dataTask{
		isDelete: true,
		dataType: dataType,
		dataKey:  dataKey,
		data:     data,
	}
	var postTask *dataTask
	if postTask, err = es.transformData(preTask); err == nil {
		err = es.scheduleTask(postTask)
	}
	return
}

func (es *enterpriseStorage) Clear() {
	_ = es.settingStorage.Delete()
	_ = es.dataStorage.Clear()
}

type dataTask struct {
	isDelete bool
	dataType int32
	dataKey  string
	data     []byte
}
