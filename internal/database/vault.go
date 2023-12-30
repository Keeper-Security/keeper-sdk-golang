package database

type RecordStorage struct {
	RecordUid_    string `db:"record_uid"`
	Revision_     int64  `db:"revision"`
	Version_      int32  `db:"version"`
	ModifiedTime_ int64  `db:"modified_time"`
	Data_         []byte `db:"data"`
	Extra_        []byte `db:"extra"`
	UData_        string `db:"udata"`
	Shared_       bool   `db:"shared"`
}

func (r *RecordStorage) RecordUid() string {
	return r.RecordUid_
}
func (r *RecordStorage) Revision() int64 {
	return r.Revision_
}
func (r *RecordStorage) Version() int32 {
	return r.Version_
}
func (r *RecordStorage) ModifiedTime() int64 {
	return r.ModifiedTime_
}
func (r *RecordStorage) Data() []byte {
	return r.Data_
}
func (r *RecordStorage) Extra() []byte {
	return r.Extra_
}
func (r *RecordStorage) UData() string {
	return r.UData_
}
func (r *RecordStorage) Shared() bool {
	return r.Shared_
}
func (r *RecordStorage) SetShared(shared bool) {
	r.Shared_ = shared
}
func (r *RecordStorage) Uid() string {
	return r.RecordUid()
}

type NonSharedDataStorage struct {
	RecordUid_ string `db:"record_uid"`
	Data_      []byte `db:"data"`
}

func (nsd *NonSharedDataStorage) RecordUid() string {
	return nsd.RecordUid_
}
func (nsd *NonSharedDataStorage) Data() []byte {
	return nsd.Data_
}
func (nsd *NonSharedDataStorage) Uid() string {
	return nsd.RecordUid()
}

type SharedFolderStorage struct {
	SharedFolderUid_      string `db:"shared_folder_uid"`
	Revision_             int64  `db:"revision"`
	Name_                 []byte `db:"name"`
	Data_                 []byte `db:"data"`
	DefaultManageRecords_ bool   `db:"default_manage_records"`
	DefaultManageUsers_   bool   `db:"default_manage_users"`
	DefaultCanEdit_       bool   `db:"default_can_edit"`
	DefaultCanShare_      bool   `db:"default_can_share"`
	OwnerAccountUid_      string `db:"owner_account_uid"`
}

func (sf *SharedFolderStorage) SharedFolderUid() string {
	return sf.SharedFolderUid_
}
func (sf *SharedFolderStorage) Revision() (revision int64) {
	return sf.Revision_
}
func (sf *SharedFolderStorage) Name() []byte {
	return sf.Name_
}
func (sf *SharedFolderStorage) Data() []byte {
	return sf.Data_
}
func (sf *SharedFolderStorage) DefaultManageRecords() bool {
	return sf.DefaultManageRecords_
}
func (sf *SharedFolderStorage) DefaultManageUsers() bool {
	return sf.DefaultManageUsers_
}
func (sf *SharedFolderStorage) DefaultCanEdit() bool {
	return sf.DefaultCanEdit_
}
func (sf *SharedFolderStorage) DefaultCanShare() bool {
	return sf.DefaultCanShare_
}
func (sf *SharedFolderStorage) OwnerAccountUid() string {
	return sf.OwnerAccountUid_
}
func (sf *SharedFolderStorage) Uid() string {
	return sf.SharedFolderUid()
}

type TeamStorage struct {
	TeamUid_        string `db:"team_uid"`
	Name_           string `db:"name"`
	TeamKey_        []byte `db:"team_key"`
	KeyType_        int32  `db:"key_type"`
	TeamPrivateKey_ []byte `db:"team_private_key"`
	RestrictEdit_   bool   `db:"restrict_edit"`
	RestrictShare_  bool   `db:"restrict_share"`
	RestrictView_   bool   `db:"restrict_view"`
}

func (t *TeamStorage) TeamUid() string {
	return t.TeamUid_
}
func (t *TeamStorage) Name() string {
	return t.Name_
}
func (t *TeamStorage) TeamKey() []byte {
	return t.TeamKey_
}
func (t *TeamStorage) KeyType() int32 {
	return t.KeyType_
}
func (t *TeamStorage) TeamPrivateKey() []byte {
	return t.TeamPrivateKey_
}
func (t *TeamStorage) RestrictEdit() (b bool) {
	return t.RestrictEdit_
}
func (t *TeamStorage) RestrictShare() (b bool) {
	return t.RestrictShare_
}
func (t *TeamStorage) RestrictView() (b bool) {
	return t.RestrictView_
}
func (t *TeamStorage) Uid() string {
	return t.TeamUid()
}

type FolderStorage struct {
	FolderUid_       string `db:"folder_uid"`
	ParentUid_       string `db:"parent_uid"`
	FolderType_      string `db:"folder_type"`
	FolderKey_       []byte `db:"folder_key"`
	KeyType_         int32  `db:"key_type"`
	SharedFolderUid_ string `db:"shared_folder_uid"`
	Revision_        int64  `db:"revision"`
	Data_            []byte `db:"data"`
}

func (f *FolderStorage) FolderUid() string {
	return f.FolderUid_
}
func (f *FolderStorage) SharedFolderUid() string {
	return f.SharedFolderUid_
}
func (f *FolderStorage) ParentUid() string {
	return f.ParentUid_
}
func (f *FolderStorage) FolderType() string {
	return f.FolderType_
}
func (f *FolderStorage) Revision() int64 {
	return f.Revision_
}
func (f *FolderStorage) FolderKey() []byte {
	return f.FolderKey_
}
func (f *FolderStorage) KeyType() int32 {
	return f.KeyType_
}
func (f *FolderStorage) Data() []byte {
	return f.Data_
}
func (f *FolderStorage) Uid() string {
	return f.FolderUid()
}

type RecordTypeStorage struct {
	Id_      int64  `db:"id"`
	Scope_   int32  `db:"scope"`
	Content_ string `db:"content"`
}

func (f *RecordTypeStorage) Id() int64 {
	return f.Id_
}
func (f *RecordTypeStorage) Scope() int32 {
	return f.Scope_
}
func (f *RecordTypeStorage) Content() string {
	return f.Content_
}
func (f *RecordTypeStorage) Uid() int64 {
	return f.Id()
}

type UserEmailStorage struct {
	AccountUid_ string `db:"account_uid"`
	Email_      string `db:"email"`
}

func (ues *UserEmailStorage) AccountUid() string {
	return ues.AccountUid_
}

func (ues *UserEmailStorage) Email() string {
	return ues.Email_
}
func (ues *UserEmailStorage) SubjectUid() string {
	return ues.AccountUid()
}
func (ues *UserEmailStorage) ObjectUid() string {
	return ues.Email()
}

type RecordKeyStorage struct {
	RecordUid_       string `db:"record_uid"`
	EncrypterUid_    string `db:"encrypter_uid"`
	KeyType_         int32  `db:"key_type"`
	RecordKey_       []byte `db:"record_key"`
	CanShare_        bool   `db:"can_share"`
	CanEdit_         bool   `db:"can_edit"`
	ExpirationTime_  int64  `db:"expiration_time"`
	Owner_           bool   `db:"owner"`
	OwnerAccountUid_ string `db:"owner_account_uid"`
}

func (rks *RecordKeyStorage) RecordUid() string {
	return rks.RecordUid_
}
func (rks *RecordKeyStorage) EncrypterUid() string {
	return rks.EncrypterUid_
}
func (rks *RecordKeyStorage) KeyType() int32 {
	return rks.KeyType_
}
func (rks *RecordKeyStorage) RecordKey() []byte {
	return rks.RecordKey_
}
func (rks *RecordKeyStorage) CanShare() bool {
	return rks.CanShare_
}
func (rks *RecordKeyStorage) CanEdit() bool {
	return rks.CanEdit_
}
func (rks *RecordKeyStorage) ExpirationTime() int64 {
	return rks.ExpirationTime_
}
func (rks *RecordKeyStorage) Owner() bool {
	return rks.Owner_
}
func (rks *RecordKeyStorage) OwnerAccountUid() string {
	return rks.OwnerAccountUid_
}
func (rks *RecordKeyStorage) SubjectUid() string {
	return rks.RecordUid()
}
func (rks *RecordKeyStorage) ObjectUid() string {
	return rks.EncrypterUid()
}

type SharedFolderKeyStorage struct {
	SharedFolderUid_ string `db:"shared_folder_uid"`
	EncrypterUid_    string `db:"encrypter_uid"`
	KeyType_         int32  `db:"key_type"`
	SharedFolderKey_ []byte `db:"shared_folder_key"`
}

func (sfk *SharedFolderKeyStorage) SharedFolderUid() string {
	return sfk.SharedFolderUid_
}
func (sfk *SharedFolderKeyStorage) EncrypterUid() string {
	return sfk.EncrypterUid_
}
func (sfk *SharedFolderKeyStorage) KeyType() int32 {
	return sfk.KeyType_
}
func (sfk *SharedFolderKeyStorage) SharedFolderKey() []byte {
	return sfk.SharedFolderKey_
}
func (sfk *SharedFolderKeyStorage) SubjectUid() string {
	return sfk.SharedFolderUid()
}
func (sfk *SharedFolderKeyStorage) ObjectUid() string {
	return sfk.EncrypterUid()
}

type SharedFolderPermissionStorage struct {
	SharedFolderUid_ string `db:"shared_folder_uid"`
	UserUid_         string `db:"user_uid"`
	UserType_        int32  `db:"user_type"`
	ManageRecords_   bool   `db:"manage_records"`
	ManageUsers_     bool   `db:"manage_users"`
	ExpirationTime_  int64  `db:"expiration_time"`
}

func (sfp *SharedFolderPermissionStorage) SharedFolderUid() string {
	return sfp.SharedFolderUid_
}
func (sfp *SharedFolderPermissionStorage) UserUid() string {
	return sfp.UserUid_
}
func (sfp *SharedFolderPermissionStorage) UserType() int32 {
	return sfp.UserType_
}
func (sfp *SharedFolderPermissionStorage) ManageRecords() bool {
	return sfp.ManageRecords_
}
func (sfp *SharedFolderPermissionStorage) ManageUsers() bool {
	return sfp.ManageUsers_
}
func (sfp *SharedFolderPermissionStorage) ExpirationTime() int64 {
	return sfp.ExpirationTime_
}
func (sfp *SharedFolderPermissionStorage) SubjectUid() string {
	return sfp.SharedFolderUid()
}
func (sfp *SharedFolderPermissionStorage) ObjectUid() string {
	return sfp.UserUid()
}

type FolderRecordStorage struct {
	FolderUid_ string `db:"folder_uid"`
	RecordUid_ string `db:"record_uid"`
}

func (fr *FolderRecordStorage) FolderUid() string {
	return fr.FolderUid_
}
func (fr *FolderRecordStorage) RecordUid() string {
	return fr.RecordUid_
}
func (fr *FolderRecordStorage) SubjectUid() string {
	return fr.FolderUid()
}
func (fr *FolderRecordStorage) ObjectUid() string {
	return fr.RecordUid()
}

type BreachWatchRecordStorage struct {
	RecordUid_ string `db:"record_uid"`
	Data_      []byte `db:"data"`
	Type_      int32  `db:"type"`
	Revision_  int64  `db:"revision"`
}

func (bwr *BreachWatchRecordStorage) RecordUid() string {
	return bwr.RecordUid_
}
func (bwr *BreachWatchRecordStorage) Data() []byte {
	return bwr.Data_
}
func (bwr *BreachWatchRecordStorage) Type() int32 {
	return bwr.Type_
}
func (bwr *BreachWatchRecordStorage) Revision() int64 {
	return bwr.Revision_
}
func (bwr *BreachWatchRecordStorage) Uid() string {
	return bwr.RecordUid()
}

type BreachWatchSecurityData struct {
	RecordUid_ string `db:"record_uid"`
	Revision_  int64  `db:"revision"`
}

func (bwsd *BreachWatchSecurityData) RecordUid() string {
	return bwsd.RecordUid_
}
func (bwsd *BreachWatchSecurityData) Revision() int64 {
	return bwsd.Revision_
}
func (bwsd *BreachWatchSecurityData) Uid() string {
	return bwsd.RecordUid()
}

type UserSettingsStorage struct {
	ContinuationToken_ []byte `db:"continuation_token"`
	ProfileData_       []byte `db:"profile_data"`
	ProfileName_       string `db:"profile_name"`
	ProfileUrl_        string `db:"profile_url"`
}

func (us *UserSettingsStorage) ContinuationToken() []byte {
	return us.ContinuationToken_
}
func (us *UserSettingsStorage) ProfileData() []byte {
	return us.ProfileData_
}
func (us *UserSettingsStorage) ProfileName() string {
	return us.ProfileName_
}
func (us *UserSettingsStorage) ProfileUrl() string {
	return us.ProfileUrl_
}
func (us *UserSettingsStorage) SetContinuationToken(token []byte) {
	us.ContinuationToken_ = token
}
func (us *UserSettingsStorage) SetProfileData(data []byte) {
	us.ProfileData_ = data
}
func (us *UserSettingsStorage) SetProfileName(name string) {
	us.ProfileName_ = name
}
func (us *UserSettingsStorage) SetProfileUrl(url string) {
	us.ProfileUrl_ = url
}
