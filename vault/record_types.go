package vault

import (
	"encoding/json"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/auth"
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_record"
	"github.com/keeper-security/keeper-sdk-golang/storage"
)

type IRecordTypeField interface {
	FieldType() string
	Label() string
	Required() bool
}
type IRecordType interface {
	Id() int64
	Name() string
	Scope() RecordTypeScope
	Description() string
	Fields() []IRecordTypeField
	storage.IUid[string]
}

func ParseRecordType(srt IStorageRecordType) (irt IRecordType, err error) {
	var rt = new(database.RecordTypeContent)
	if err = json.Unmarshal([]byte(srt.Content()), rt); err != nil {
		return
	}
	irt = &recordType{
		id:          srt.Id(),
		name:        rt.Name,
		scope:       RecordTypeScope(srt.Scope()),
		description: rt.Description,
		fields: api.SliceSelect(rt.Fields, func(x *database.RecordTypeField) IRecordTypeField {
			return &recordTypeField{
				fieldType: x.Type,
				label:     x.Label,
				required:  x.Required,
			}
		}),
	}
	return
}

type recordTypeField struct {
	fieldType string
	label     string
	required  bool
}

func (rtf *recordTypeField) FieldType() string {
	return rtf.fieldType
}
func (rtf *recordTypeField) Label() string {
	return rtf.label
}
func (rtf *recordTypeField) Required() bool {
	return rtf.required
}

type recordType struct {
	id          int64
	name        string
	scope       RecordTypeScope
	description string
	fields      []IRecordTypeField
}

func (rt *recordType) Id() int64 {
	return rt.id
}
func (rt *recordType) Name() string {
	return rt.name
}
func (rt *recordType) Scope() RecordTypeScope {
	return rt.scope
}
func (rt *recordType) Description() string {
	return rt.description
}
func (rt *recordType) Fields() []IRecordTypeField {
	return rt.fields
}
func (rt *recordType) Uid() string {
	return rt.Name()
}

func LoadRecordTypes(keeperAuth auth.IKeeperAuth, storage storage.IEntityStorage[IStorageRecordType, int64]) (err error) {
	var rq = &proto_record.RecordTypesRequest{
		Standard:   true,
		User:       true,
		Enterprise: true,
		Pam:        true,
	}
	var rs = new(proto_record.RecordTypesResponse)
	if err = keeperAuth.ExecuteAuthRest("vault/get_record_types", rq, rs); err == nil {
		err = storage.PutEntities(api.SliceSelect(rs.RecordTypes, func(x *proto_record.RecordType) IStorageRecordType {
			return &database.RecordTypeStorage{
				Id_:      int64(x.Scope)<<32 + int64(x.RecordTypeId),
				Scope_:   int32(x.Scope),
				Content_: x.Content,
			}
		}))
	}
	return
}
