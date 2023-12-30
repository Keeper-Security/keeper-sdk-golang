package enterprise

import (
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/sqlite"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	_ "github.com/mattn/go-sqlite3"
	"gotest.tools/assert"
	"reflect"
	"testing"
)

func TestExtract(t *testing.T) {
	var entityType = reflect.TypeOf((*database.EnterpriseEntityData)(nil))
	var ts, err = sqlite.LoadTableSchema(entityType, []string{"type", "key"}, nil,
		"enterprise_id", sqlite.SqlDataType_Integer)
	assert.NilError(t, err)
	//var connectionString = "file:///Users/skolupaev/.keeper/keeper_test_db.sqlite?cache=shared&mode=rwc"
	var connectionString = "file::memory:?cache=shared&mode=memory"
	var db *sqlx.DB
	db, err = sqlx.Connect("sqlite3", connectionString)
	assert.NilError(t, err)
	var queries []string
	queries, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{ts}, true)
	assert.Check(t, len(queries) == 0)
	assert.NilError(t, err)

	var eedStorage storage.ILinkStorage[*database.EnterpriseEntityData, int64, string]
	eedStorage, err = sqlite.NewSqliteLinkStorage[*database.EnterpriseEntityData, int64, string](
		func() *sqlx.DB { return db }, ts, 12345)
	assert.NilError(t, err)
	var es []*database.EnterpriseEntityData
	var eed = &database.EnterpriseEntityData{
		Type: 10,
		Key:  "qqqqqq",
		Data: []byte("fdsfdsfdsfdsfdsfsdfdssd"),
	}
	es = append(es, eed)
	err = eedStorage.PutLinks(es)
	assert.NilError(t, err)
	es = nil
	err = eedStorage.GetAll(func(data *database.EnterpriseEntityData) bool {
		es = append(es, data)
		return true
	})
	assert.NilError(t, err)
	assert.Check(t, len(es) == 1)

	es = nil
	err = eedStorage.GetLinksForSubjects([]int64{10}, func(data *database.EnterpriseEntityData) bool {
		es = append(es, data)
		return true
	})
	assert.NilError(t, err)
	assert.Check(t, len(es) == 1)

	es = nil
	err = eedStorage.GetLinksForObjects([]string{"qqqqqq"}, func(data *database.EnterpriseEntityData) bool {
		es = append(es, data)
		return true
	})
	assert.NilError(t, err)
	assert.Check(t, len(es) == 1)

	var eed1 *database.EnterpriseEntityData
	eed1, err = eedStorage.GetLink(10, "qqqqqq")
	assert.NilError(t, err)
	assert.Check(t, eed1.Type == 10)

	err = eedStorage.DeleteLinks([]storage.IUidLink[int64, string]{storage.NewUidLink[int64, string](10, "qqqqqq")})
	assert.NilError(t, err)

	eed1, err = eedStorage.GetLink(10, "qqqqqq")
	assert.NilError(t, err)
	assert.Check(t, eed1 == nil)
}
