package database

type RecordTypeField struct {
	Type     string `json:"$ref"`
	Label    string `json:"label"`
	Required bool   `json:"required"`
}

type RecordTypeContent struct {
	Name        string             `json:"$id"`
	Description string             `json:"description"`
	Fields      []*RecordTypeField `json:"fields"`
}
