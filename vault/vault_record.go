package vault

type IKeeperRecord interface {
	RecordUid() string
	Version() int32
	Title() string
	TimeModified() int64
}

type ICustomField interface {
	Name() string
	Value() string
	Type() string
}

type IPasswordRecord interface {
	IKeeperRecord
	Login() string
	Password() string
	Link() string
	Notes() string
	Custom() []ICustomField
	Totp() string
	SetTitle(string)
	SetLogin(string)
	SetPassword(string)
	SetLink(string)
	SetNotes(string)
	SetTotp(string)
	SetCustomField(string, string)
}
