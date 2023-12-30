package vault

type IRecordInfo interface {
	RecordUid() string
	Version() int32
	Revision() int64
	RecordType() string
	Title() string
	Url() string
	Description() string
	Owner() bool
	Shared() bool
	HasAttachments() bool
}

type IVaultData interface {
	VaultStorage() IVaultStorage
	ClientKey() []byte
	GetAllRecords(func(IRecordInfo) bool)
	GetRecord(string) IRecordInfo
	GetRecordKey(string) []byte
	RecordCount() int
}
