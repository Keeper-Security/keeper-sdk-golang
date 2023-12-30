package sqlite

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/storage"
)

type ConnectionGetter func() *sqlx.DB

func NewSqliteRecordStorage[T any](
	getConnection ConnectionGetter, schema ITableSchema, ownerValue interface{}) (rto storage.IRecordStorage[T], err error) {

	rto = &sqliteRecordStorage[T]{
		sqliteStorage[T]{
			getConnection: getConnection,
			schema:        schema,
			ownerValue:    ownerValue,
			queryCache:    make(map[string]string),
		},
	}
	return
}

type sqliteRecordStorage[T any] struct {
	sqliteStorage[T]
}

func (srs *sqliteRecordStorage[T]) Load() (record T, err error) {
	err = srs.SelectAll(func(r T) bool {
		record = r
		return false
	})
	return
}
func (srs *sqliteRecordStorage[T]) Store(record T) (err error) {
	err = srs.Put([]T{record})
	return
}
func (srs *sqliteRecordStorage[T]) Delete() (err error) {
	err = srs.DeleteAll()
	return
}

func NewSqliteEntityStorage[T any, K storage.Key](
	getConnection ConnectionGetter, schema ITableSchema, ownerValue interface{}) (sto storage.IEntityStorage[T, K], err error) {
	if len(schema.PrimaryKey()) != 1 {
		err = api.NewKeeperError(fmt.Sprintf(
			"SqliteEntityStorage (%s): Primary key to have one column.", schema.TableName()))
	}

	sto = &sqliteEntityStorage[T, K]{
		sqliteStorage[T]{
			getConnection: getConnection,
			schema:        schema,
			ownerValue:    ownerValue,
			queryCache:    make(map[string]string),
		},
	}
	return
}

type sqliteEntityStorage[T any, K storage.Key] struct {
	sqliteStorage[T]
}

func (ses *sqliteEntityStorage[T, K]) GetEntity(key K) (entity T, err error) {
	var returned = false
	err = ses.SelectFilter(ses.Schema().PrimaryKey(), [][]interface{}{{key}}, func(t T) bool {
		if returned {
			err = api.NewKeeperError(fmt.Sprintf("Get Entity: more than a one record for UID %v", key))
		} else {
			entity = t
			returned = true
		}
		return true
	})
	return
}

func (ses *sqliteEntityStorage[T, K]) GetAll(cb func(T) bool) error {
	return ses.sqliteStorage.SelectAll(func(entity T) bool {
		return cb(entity)
	})
}

func (ses *sqliteEntityStorage[T, K]) PutEntities(entities []T) (err error) {
	return ses.Put(entities)
}

func (ses *sqliteEntityStorage[T, K]) DeleteUids(uids []K) error {
	var values = make([][]interface{}, len(uids))
	for i, e := range uids {
		values[i] = []interface{}{e}
	}
	return ses.DeleteFilter(ses.schema.PrimaryKey(), values)
}
func (ses *sqliteEntityStorage[T, K]) Clear() error {
	return ses.DeleteAll()
}

func NewSqliteLinkStorage[T any, KS storage.Key, KO storage.Key](
	getConnection ConnectionGetter, schema ITableSchema,
	ownerValue interface{}) (sto storage.ILinkStorage[T, KS, KO], err error) {
	if len(schema.PrimaryKey()) != 2 {
		err = api.NewKeeperError(fmt.Sprintf(
			"SqliteLinkStorage (%s): Primary key to have two columns.", schema.TableName()))
	}
	var objectColumn = schema.PrimaryKey()[1]
	var objectIndexName string
	if schema.Indexes() != nil {
		for k, v := range schema.Indexes() {
			if v[0] == objectColumn {
				objectIndexName = k
				break
			}
		}
	}
	if len(objectIndexName) == 0 {
		err = api.NewKeeperError(fmt.Sprintf(
			"SqliteLinkStorage: ObjectUID column \"%s\"is not indexed in the table \"%s\".",
			objectColumn, schema.TableName()))
	}

	sto = &sqliteLinkStorage[T, KS, KO]{
		sqliteStorage[T]{
			getConnection: getConnection,
			schema:        schema,
			ownerValue:    ownerValue,
			queryCache:    make(map[string]string),
		},
	}
	return
}

type sqliteLinkStorage[T any, KS storage.Key, KO storage.Key] struct {
	sqliteStorage[T]
}

func (sls *sqliteLinkStorage[T, KS, KO]) PutLinks(links []T) (err error) {
	return sls.Put(links)
}
func (sls *sqliteLinkStorage[T, KS, KO]) DeleteLinks(links []storage.IUidLink[KS, KO]) (err error) {
	var values = make([][]interface{}, len(links))
	for i, e := range links {
		values[i] = []interface{}{e.SubjectUid(), e.ObjectUid()}
	}
	return sls.DeleteFilter(sls.schema.PrimaryKey(), values)
}
func (sls *sqliteLinkStorage[T, KS, KO]) DeleteLinksForObjects(objects []KO) (err error) {
	var values = make([][]interface{}, len(objects))
	for i, e := range objects {
		values[i] = []interface{}{e}
	}
	return sls.DeleteFilter([]string{sls.schema.PrimaryKey()[1]}, values)
}
func (sls *sqliteLinkStorage[T, KS, KO]) DeleteLinksForSubjects(subjects []KS) (err error) {
	var values = make([][]interface{}, len(subjects))
	for i, e := range subjects {
		values[i] = []interface{}{e}
	}
	return sls.DeleteFilter([]string{sls.schema.PrimaryKey()[0]}, values)
}
func (sls *sqliteLinkStorage[T, KS, KO]) GetLinksForObjects(objects []KO, cb func(link T) bool) (err error) {
	var values = make([][]interface{}, len(objects))
	for i, e := range objects {
		values[i] = []interface{}{e}
	}
	return sls.SelectFilter([]string{sls.schema.PrimaryKey()[1]}, values, cb)
}
func (sls *sqliteLinkStorage[T, KS, KO]) GetLinksForSubjects(subjects []KS, cb func(T) bool) (err error) {
	var values = make([][]interface{}, len(subjects))
	for i, e := range subjects {
		values[i] = []interface{}{e}
	}
	return sls.SelectFilter([]string{sls.schema.PrimaryKey()[0]}, values, cb)
}
func (sls *sqliteLinkStorage[T, KS, KO]) GetAll(cb func(T) bool) (err error) {
	return sls.SelectAll(cb)
}
func (sls *sqliteLinkStorage[T, KS, KO]) GetLink(subjectKey KS, objectKey KO) (link T, err error) {
	err = sls.SelectFilter(sls.schema.PrimaryKey(), [][]interface{}{{subjectKey, objectKey}}, func(t T) bool {
		link = t
		return false
	})
	return
}
func (sls *sqliteLinkStorage[T, KS, KO]) Clear() error {
	return sls.DeleteAll()
}
