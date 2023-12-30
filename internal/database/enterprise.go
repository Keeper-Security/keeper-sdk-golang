package database

type EnterpriseSettings struct {
	ContinuationToken []byte `db:"continuation_token"`
	EnterpriseIds     string `db:"enterprise_ids"`
}

type EnterpriseEntityData struct {
	Type int64  `db:"type"`
	Key  string `db:"key"`
	Data []byte `db:"data"`
}

type EncryptedData struct {
	DisplayName string `json:"displayname,omitempty"`
}
