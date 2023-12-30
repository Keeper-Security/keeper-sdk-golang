package main

import (
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/auth"
	"github.com/keeper-security/keeper-sdk-golang/enterprise"
	"github.com/keeper-security/keeper-sdk-golang/vault"
	_ "github.com/mattn/go-sqlite3"
)

type IAaa interface {
	Uid() string
	Value() int64
}

type aaa struct {
	uid   string `db:"uid"`
	value int64  `db:"value"`
}

func (a *aaa) Uid() string {
	return a.uid
}
func (a *aaa) Value() int64 {
	return a.value
}

func main() {
	var err error
	//var connectionString = "file::memory:?cache=shared&mode=memory"
	//var db *sqlx.DB
	//db, err = sqlx.Connect("sqlite3", connectionString)
	//if err != nil {
	//	panic(err)
	//}
	//
	//var entityType = reflect.TypeOf((*aaa)(nil))
	//var ts sqlite.ITableSchema
	//
	//ts, err = sqlite.LoadTableSchema(entityType, []string{"uid"}, nil,
	//	"enterprise_id", sqlite.SqlDataType_Integer)
	//if err != nil {
	//	panic(err)
	//}
	//var queries []string
	//queries, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{ts}, true)
	//if len(queries) > 0 {
	//	panic("create table")
	//}
	//var ent storage.IEntityStorage[IAaa, string]
	//ent, err = sqlite.NewSqliteEntityStorage[IAaa, string](func() *sqlx.DB { return db }, ts, 4)
	//if err != nil {
	//	panic(err)
	//}
	//err = ent.PutEntities([]IAaa{&aaa{
	//	uid:   "sdfdsfsdfsdf",
	//	value: 10,
	//}})
	//if err != nil {
	//	panic(err)
	//}

	//var configStorage = helpers.NewCommanderConfiguration("")
	var configStorage = auth.NewJsonConfigurationFile("")
	var config auth.IKeeperConfiguration
	if config, err = configStorage.Get(); err != nil {
		panic(err)
	}

	var endpoint = auth.NewKeeperEndpoint(config.LastServer(), configStorage)
	var loginAuth = auth.NewLoginAuth(endpoint)
	loginAuth.Login(config.LastLogin())
	var step = loginAuth.Step()
	if step.LoginState() != auth.LoginState_Connected {
		panic(fmt.Sprintf("Invalid login state: %v", step.LoginState()))
	}
	var ok bool
	var connectedStep auth.IConnectedStep
	if connectedStep, ok = step.(auth.IConnectedStep); !ok {
		panic(step)
	}
	var keeperAuth auth.IKeeperAuth
	if keeperAuth, err = connectedStep.TakeKeeperAuth(); err != nil {
		panic(err)
	}

	var storage enterprise.IEnterpriseStorage
	//storage, err = enterprise.NewSqliteEnterpriseStorage(func() *sqlx.DB { return db }, int64(keeperAuth.AuthContext().License().EnterpriseId))
	var loader = enterprise.NewEnterpriseLoader(keeperAuth, storage)
	if err = loader.Load(); err != nil {
		panic(err)
	}
	loader.EnterpriseData().RecordTypes().GetAllEntities(func(x vault.IRecordType) bool {
		if x.Scope() == vault.RecordTypeScope_Standard {
			fmt.Printf("- `%s` %s\n", x.Name(), x.Description())
		}
		return true
	})

}
