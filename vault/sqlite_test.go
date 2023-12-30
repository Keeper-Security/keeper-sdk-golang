package vault

import (
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/sqlite"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	_ "github.com/mattn/go-sqlite3"
	"gotest.tools/assert"
	"reflect"
	"testing"
)

func TestEntityStorage(t *testing.T) {
	var entityType = reflect.TypeOf((*database.RecordStorage)(nil))
	var ts, err = sqlite.LoadTableSchema(entityType, []string{"record_uid"}, nil,
		"account_uid", sqlite.SqlDataType_String)
	assert.NilError(t, err)
	var connectionString = "file:///Users/skolupaev/.keeper/keeper_db_test.sqlite?cache=shared&mode=rwc"
	// var connectionString = "file::memory:?cache=shared&mode=memory"
	var db *sqlx.DB
	db, err = sqlx.Connect("sqlite3", connectionString)
	assert.NilError(t, err)
	ts.SetTableName("StorageRecord")
	var queries []string
	queries, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{ts}, true)
	assert.Assert(t, len(queries) == 0)
	assert.NilError(t, err)

	var ees storage.IEntityStorage[IStorageRecord, string]
	ees, err = sqlite.NewSqliteEntityStorage[IStorageRecord, string](func() *sqlx.DB { return db }, ts, "xxx")
	assert.NilError(t, err)

	err = ees.Clear()
	assert.NilError(t, err)

	var r1 = &database.RecordStorage{
		RecordUid_:    api.Base64UrlEncode(api.GenerateUid()),
		ModifiedTime_: 3232320,
		Version_:      10,
		Data_:         []byte("DATA"),
		Extra_:        nil,
		UData_:        "",
		Revision_:     2,
		Shared_:       true,
	}

	var r2 = &database.RecordStorage{
		RecordUid_:    api.Base64UrlEncode(api.GenerateUid()),
		ModifiedTime_: 3232320,
		Version_:      11,
		Data_:         []byte("DATA"),
		Extra_:        []byte("EXTRA"),
		UData_:        "UDATA",
		Revision_:     3,
		Shared_:       false,
	}

	err = ees.PutEntities([]IStorageRecord{r1, r2})
	assert.NilError(t, err)

	var rb1 IStorageRecord
	rb1, err = ees.GetEntity(r1.RecordUid())
	assert.NilError(t, err)
	assert.Check(t, rb1 != nil)

	var cnt = 0
	err = ees.GetAll(func(r IStorageRecord) bool {
		cnt++
		return true
	})
	assert.NilError(t, err)
	assert.Check(t, cnt == 2)
	assert.Check(t, rb1 != nil)
}
