package storage

import (
	"github.com/keeper-security/keeper-sdk-golang/api"
	"gotest.tools/assert"
	"testing"
	"time"
)

type IRecord interface {
	Id() string
	ModifiedTime() int64
	Data() []byte
	UData() string
	Shared() bool
}

type TRecord struct {
	Id_           string `db:"id"`
	ModifiedTime_ int64  `db:"modified_time"`
	Data_         []byte `db:"data"`
	UData_        string `db:"udata"`
	Shared_       bool   `db:"shared"`
}

func (r *TRecord) Id() string {
	return r.Id_
}
func (r *TRecord) ModifiedTime() int64 {
	return r.ModifiedTime_
}
func (r *TRecord) Data() []byte {
	return r.Data_
}
func (r *TRecord) UData() string {
	return r.UData_
}
func (r *TRecord) Shared() bool {
	return r.Shared_
}

var _ IRecord = new(TRecord)

func TestEntityStorage(t *testing.T) {
	var recordStorage = NewInMemoryEntityStorage[IRecord, string](func(record IRecord) string {
		return record.Id()
	})
	var uid = api.Base64UrlEncode(api.GenerateUid())
	var r = &TRecord{
		Id_:           uid,
		ModifiedTime_: time.Now().UnixMilli(),
		Data_:         []byte("DATA"),
		UData_:        "{}",
		Shared_:       false,
	}

	var err = recordStorage.PutEntities([]IRecord{r})
	assert.NilError(t, err)
	var r1 IRecord
	r1, err = recordStorage.GetEntity(uid)
	assert.NilError(t, err)
	assert.Assert(t, r == r1)
	err = recordStorage.DeleteUids([]string{uid, uid})
	assert.NilError(t, err)
}
