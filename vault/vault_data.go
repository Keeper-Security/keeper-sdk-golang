package vault

var (
	_ IVaultData  = new(vaultData)
	_ IRecordInfo = new(recordInfo)
)

type recordInfo struct {
	recordUid      string
	version        int32
	revision       int64
	recordType     string
	title          string
	url            string
	description    string
	owner          bool
	shared         bool
	hasAttachments bool
}

func (ri *recordInfo) RecordUid() string    { return ri.recordUid }
func (ri *recordInfo) Version() int32       { return ri.version }
func (ri *recordInfo) Revision() int64      { return ri.revision }
func (ri *recordInfo) RecordType() string   { return ri.recordType }
func (ri *recordInfo) Title() string        { return ri.title }
func (ri *recordInfo) Url() string          { return ri.url }
func (ri *recordInfo) Description() string  { return ri.description }
func (ri *recordInfo) Owner() bool          { return ri.owner }
func (ri *recordInfo) Shared() bool         { return ri.shared }
func (ri *recordInfo) HasAttachments() bool { return ri.hasAttachments }

type loadedRecord struct {
	recordInfo recordInfo
	recordKey  []byte
}

type vaultData struct {
	clientKey    []byte
	vaultStorage IVaultStorage
	records      map[string]*loadedRecord
}

func (vd *vaultData) VaultStorage() IVaultStorage { return vd.vaultStorage }
func (vd *vaultData) ClientKey() []byte           { return vd.clientKey }
func (vd *vaultData) GetAllRecords(cb func(IRecordInfo) bool) {
	for _, e := range vd.records {
		if !cb(&(e.recordInfo)) {
			return
		}
	}
}
func (vd *vaultData) GetRecord(recordUid string) (ri IRecordInfo) {
	var ok bool
	var lr *loadedRecord
	if lr, ok = vd.records[recordUid]; ok {
		ri = &(lr.recordInfo)
	}
	return
}
func (vd *vaultData) RecordCount() int {
	return len(vd.records)
}
func (vd *vaultData) GetRecordKey(recordUid string) (key []byte) {
	var ok bool
	var lr *loadedRecord
	if lr, ok = vd.records[recordUid]; ok {
		key = lr.recordKey
	}
	return
}
