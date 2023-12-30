package enterprise

import (
	"github.com/keeper-security/keeper-sdk-golang/api"
	"strings"
)

type license struct {
	enterpriseLicenseId int64
	licenseKeyId        int32
	productTypeId       int32
	filePlanId          int32
	name                string
	numberOfSeats       int32
	seatsAllocated      int32
	seatsPending        int32
	addOns              []ILicenseAddOn
	licenseStatus       string
	nextBillingDate     int64
	expiration          int64
	storageExpiration   int64
	distributor         bool
	mspPermits          []IMspPermits
	managedBy           IMspContact
}

func (l *license) EnterpriseLicenseId() int64 {
	return l.enterpriseLicenseId
}
func (l *license) LicenseKeyId() int32 {
	return l.licenseKeyId
}
func (l *license) ProductTypeId() int32 {
	return l.productTypeId
}
func (l *license) FilePlanId() int32 {
	return l.filePlanId
}
func (l *license) Name() string {
	return l.name
}
func (l *license) NumberOfSeats() int32 {
	return l.numberOfSeats
}
func (l *license) SeatsAllocated() int32 {
	return l.seatsAllocated
}
func (l *license) SeatsPending() int32 {
	return l.seatsPending
}
func (l *license) AddOns() []ILicenseAddOn {
	return l.addOns
}
func (l *license) LicenseStatus() string {
	return l.licenseStatus
}
func (l *license) NextBillingDate() int64 {
	return l.nextBillingDate
}
func (l *license) Expiration() int64 {
	return l.expiration
}
func (l *license) StorageExpiration() int64 {
	return l.storageExpiration
}
func (l *license) Distributor() bool {
	return l.distributor
}
func (l *license) MspPermits() []IMspPermits {
	return l.mspPermits
}
func (l *license) ManagedBy() IMspContact {
	return l.managedBy
}
func (l *license) Uid() int64 {
	return l.EnterpriseLicenseId()
}

type mspContact struct {
	enterpriseId   int32
	enterpriseName string
}

func (c *mspContact) EnterpriseId() int32 {
	return c.enterpriseId
}
func (c *mspContact) EnterpriseName() string {
	return c.enterpriseName
}

type mcDefaults struct {
	mcProduct        string
	filePlanType     string
	maxLicenses      int32
	addons           []string
	fixedMaxLicenses bool
}

func (mcd *mcDefaults) McProduct() string {
	return mcd.mcProduct
}
func (mcd *mcDefaults) FilePlanType() string {
	return mcd.filePlanType
}
func (mcd *mcDefaults) MaxLicenses() int32 {
	return mcd.maxLicenses
}
func (mcd *mcDefaults) Addons() []string {
	return mcd.addons
}
func (mcd *mcDefaults) FixedMaxLicenses() bool {
	return mcd.fixedMaxLicenses
}

type mspPermits struct {
	restricted             bool
	maxFilePlanType        string
	allowUnlimitedLicenses bool
	allowedMcProducts      []string
	allowedAddOns          []string
	mcDefaults             []IMcDefault
}

func (mp *mspPermits) Restricted() bool {
	return mp.restricted
}
func (mp *mspPermits) MaxFilePlanType() string {
	return mp.maxFilePlanType
}
func (mp *mspPermits) AllowUnlimitedLicenses() bool {
	return mp.allowUnlimitedLicenses
}
func (mp *mspPermits) AllowedMcProducts() []string {
	return mp.allowedMcProducts
}
func (mp *mspPermits) AllowedAddOns() []string {
	return mp.allowedAddOns
}
func (mp *mspPermits) McDefaults() []IMcDefault {
	return mp.mcDefaults
}

type licenseAddOn struct {
	name              string
	enabled           bool
	includedInProduct bool
	isTrial           bool
	seats             int32
	apiCallCount      int32
	created           int64
	activationTime    int64
	expiration        int64
}

func (la *licenseAddOn) Name() string {
	return la.name
}
func (la *licenseAddOn) Enabled() bool {
	return la.enabled
}
func (la *licenseAddOn) IncludedInProduct() bool {
	return la.includedInProduct
}
func (la *licenseAddOn) IsTrial() bool {
	return la.isTrial
}
func (la *licenseAddOn) Seats() int32 {
	return la.seats
}
func (la *licenseAddOn) ApiCallCount() int32 {
	return la.apiCallCount
}
func (la *licenseAddOn) Created() int64 {
	return la.created
}
func (la *licenseAddOn) ActivationTime() int64 {
	return la.activationTime
}
func (la *licenseAddOn) Expiration() int64 {
	return la.expiration
}

type node struct {
	nodeId               int64
	name                 string
	parentId             int64
	bridgeId             int64
	scimId               int64
	licenseId            int64
	duoEnabled           bool
	rsaEnabled           bool
	restrictVisibility   bool
	ssoServiceProviderId []int64
	encryptedData        string
}

func (n *node) NodeId() int64 {
	return n.nodeId
}
func (n *node) Name() string {
	return n.name
}
func (n *node) ParentId() int64 {
	return n.parentId
}
func (n *node) BridgeId() int64 {
	return n.bridgeId
}
func (n *node) ScimId() int64 {
	return n.scimId
}
func (n *node) LicenseId() int64 {
	return n.licenseId
}
func (n *node) DuoEnabled() bool {
	return n.duoEnabled
}
func (n *node) RsaEnabled() bool {
	return n.rsaEnabled
}
func (n *node) RestrictVisibility() bool {
	return n.restrictVisibility
}
func (n *node) SsoServiceProviderId() []int64 {
	return n.ssoServiceProviderId
}
func (n *node) EncryptedData() string {
	return n.encryptedData
}
func (n *node) SetName(name string) {
	n.name = name
}
func (n *node) SetParentId(parentId int64) {
	n.parentId = parentId
}
func (n *node) SetBridgeId(bridgeId int64) {
	n.bridgeId = bridgeId
}
func (n *node) SetScimId(scimId int64) {
	n.scimId = scimId
}
func (n *node) SetCloudSsoId(cloudSsoId int64) {
	n.ssoServiceProviderId = []int64{cloudSsoId}
}

func (n *node) SetRestrictVisibility(restrictVisibility bool) {
	n.restrictVisibility = restrictVisibility
}
func (n *node) Uid() int64 {
	return n.NodeId()
}

type role struct {
	roleId         int64
	name           string
	nodeId         int64
	keyType        string
	visibleBelow   bool
	newUserInherit bool
	roleType       string
	encryptedData  string
}

func (r *role) RoleId() int64 {
	return r.roleId
}
func (r *role) Name() string {
	return r.name
}
func (r *role) NodeId() int64 {
	return r.nodeId
}
func (r *role) KeyType() string {
	return r.keyType
}
func (r *role) VisibleBelow() bool {
	return r.visibleBelow
}
func (r *role) NewUserInherit() bool {
	return r.newUserInherit
}
func (r *role) RoleType() string {
	return r.roleType
}
func (r *role) EncryptedData() string {
	return r.encryptedData
}
func (r *role) SetName(name string) {
	r.name = name
}
func (r *role) SetNodeId(nodeId int64) {
	r.nodeId = nodeId
}
func (r *role) SetKeyType(keyType string) {
	r.keyType = keyType
}
func (r *role) SetVisibleBelow(visibleBelow bool) {
	r.visibleBelow = visibleBelow
}
func (r *role) SetNewUserInherit(newUserInherit bool) {
	r.newUserInherit = newUserInherit
}
func (r *role) Uid() int64 {
	return r.RoleId()
}

type user struct {
	enterpriseUserId         int64
	username                 string
	fullName                 string
	jobTitle                 string
	nodeId                   int64
	status                   UserStatus
	lock                     UserLock
	userId                   int32
	accountShareExpiration   int64
	tfaEnabled               bool
	transferAcceptanceStatus int32
}

func (u *user) EnterpriseUserId() int64 {
	return u.enterpriseUserId
}
func (u *user) Username() string {
	return u.username
}
func (u *user) FullName() string {
	return u.fullName
}
func (u *user) JobTitle() string {
	return u.jobTitle
}
func (u *user) NodeId() int64 {
	return u.nodeId
}
func (u *user) Status() UserStatus {
	return u.status
}
func (u *user) Lock() UserLock {
	return u.lock
}
func (u *user) UserId() int32 {
	return u.userId
}
func (u *user) AccountShareExpiration() int64 {
	return u.accountShareExpiration
}
func (u *user) TfaEnabled() bool {
	return u.tfaEnabled
}
func (u *user) TransferAcceptanceStatus() int32 {
	return u.transferAcceptanceStatus
}
func (u *user) Uid() int64 {
	return u.EnterpriseUserId()
}
func (u *user) SetFullName(fullName string) {
	u.fullName = fullName
}
func (u *user) SetJobTitle(jobTitle string) {
	u.jobTitle = jobTitle
}
func (u *user) SetNodeId(nodeId int64) {
	u.nodeId = nodeId
}
func (u *user) SetLock(lock UserLock) {
	u.lock = lock
}

type team struct {
	teamUid          string
	name             string
	nodeId           int64
	restrictEdit     bool
	restrictShare    bool
	restrictView     bool
	encryptedTeamKey []byte
}

func (t *team) TeamUid() string {
	return t.teamUid
}
func (t *team) Name() string {
	return t.name
}
func (t *team) NodeId() int64 {
	return t.nodeId
}
func (t *team) RestrictEdit() bool {
	return t.restrictEdit
}
func (t *team) RestrictShare() bool {
	return t.restrictShare
}
func (t *team) RestrictView() bool {
	return t.restrictView
}
func (t *team) EncryptedTeamKey() []byte {
	return t.encryptedTeamKey
}
func (t *team) SetName(name string) {
	t.name = name
}
func (t *team) SetNodeId(nodeId int64) {
	t.nodeId = nodeId
}
func (t *team) SetRestrictEdit(restrictEdit bool) {
	t.restrictEdit = restrictEdit
}
func (t *team) SetRestrictShare(restrictShare bool) {
	t.restrictShare = restrictShare
}
func (t *team) SetRestrictView(restrictView bool) {
	t.restrictView = restrictView
}
func (t *team) Uid() string {
	return t.TeamUid()
}

type teamUser struct {
	teamUid          string
	enterpriseUserId int64
	userType         string
}

func (tu *teamUser) TeamUid() string {
	return tu.teamUid
}
func (tu *teamUser) EnterpriseUserId() int64 {
	return tu.enterpriseUserId
}
func (tu *teamUser) UserType() string {
	return tu.userType
}
func (tu *teamUser) SetUserType(userType string) {
	switch userType {
	case "USER":
		tu.userType = "USER"
	case "ADMIN":
		tu.userType = "ADMIN"
	case "ADMIN_HIDE_SHARED_FOLDERS":
		tu.userType = "ADMIN_HIDE_SHARED_FOLDERS"
	}
}
func (tu *teamUser) SubjectUid() string {
	return tu.TeamUid()
}
func (tu *teamUser) ObjectUid() int64 {
	return tu.EnterpriseUserId()
}

type roleUser struct {
	roleId           int64
	enterpriseUserId int64
}

func (ru *roleUser) RoleId() int64 {
	return ru.roleId
}
func (ru *roleUser) EnterpriseUserId() int64 {
	return ru.enterpriseUserId
}
func (ru *roleUser) SubjectUid() int64 {
	return ru.RoleId()
}
func (ru *roleUser) ObjectUid() int64 {
	return ru.EnterpriseUserId()
}

type roleTeam struct {
	roleId  int64
	teamUid string
}

func (rt *roleTeam) RoleId() int64 {
	return rt.roleId
}
func (rt *roleTeam) TeamUid() string {
	return rt.teamUid
}
func (rt *roleTeam) SubjectUid() int64 {
	return rt.RoleId()
}
func (rt *roleTeam) ObjectUid() string {
	return rt.TeamUid()
}

type managedNode struct {
	roleId                int64
	managedNodeId         int64
	cascadeNodeManagement bool
}

func (mn *managedNode) RoleId() int64 {
	return mn.roleId
}
func (mn *managedNode) ManagedNodeId() int64 {
	return mn.managedNodeId
}
func (mn *managedNode) CascadeNodeManagement() bool {
	return mn.cascadeNodeManagement
}
func (mn *managedNode) SubjectUid() int64 {
	return mn.RoleId()
}
func (mn *managedNode) ObjectUid() int64 {
	return mn.ManagedNodeId()
}
func (mn *managedNode) SetCascadeNodeManagement(cascade bool) {
	mn.cascadeNodeManagement = cascade
}

var _ IRolePrivilegeEdit = new(rolePrivilege)

type rolePrivilege struct {
	roleId               int64
	managedNodeId        int64
	manageNodes          bool
	manageUsers          bool
	manageRoles          bool
	manageLicenses       bool
	manageTeams          bool
	runReports           bool
	manageBridge         bool
	approveDevices       bool
	manageRecordTypes    bool
	sharingAdministrator bool
	runComplianceReport  bool
	transferAccount      bool
	manageCompanies      bool
}

func (rp *rolePrivilege) RoleId() int64 {
	return rp.roleId
}
func (rp *rolePrivilege) ManagedNodeId() int64 {
	return rp.managedNodeId
}
func (rp *rolePrivilege) ManageNodes() bool          { return rp.manageNodes }
func (rp *rolePrivilege) ManageUsers() bool          { return rp.manageUsers }
func (rp *rolePrivilege) ManageRoles() bool          { return rp.manageRoles }
func (rp *rolePrivilege) ManageTeams() bool          { return rp.manageTeams }
func (rp *rolePrivilege) RunReports() bool           { return rp.runReports }
func (rp *rolePrivilege) ManageBridge() bool         { return rp.manageBridge }
func (rp *rolePrivilege) ApproveDevices() bool       { return rp.approveDevices }
func (rp *rolePrivilege) ManageRecordTypes() bool    { return rp.manageRecordTypes }
func (rp *rolePrivilege) SharingAdministrator() bool { return rp.sharingAdministrator }
func (rp *rolePrivilege) RunComplianceReport() bool  { return rp.runComplianceReport }
func (rp *rolePrivilege) TransferAccount() bool      { return rp.transferAccount }
func (rp *rolePrivilege) ManageCompanies() bool      { return rp.manageCompanies }

func (rp *rolePrivilege) ToSet() (result api.Set[string]) {
	result = api.NewSet[string]()
	if rp.manageNodes {
		result.Add(RolePrivilege_ManageNodes)
	}
	if rp.manageUsers {
		result.Add(RolePrivilege_ManageUsers)
	}
	if rp.manageRoles {
		result.Add(RolePrivilege_ManageRoles)
	}
	if rp.manageTeams {
		result.Add(RolePrivilege_ManageTeams)
	}
	if rp.runReports {
		result.Add(RolePrivilege_RunSecurityReports)
	}
	if rp.manageBridge {
		result.Add(RolePrivilege_ManageBridge)
	}
	if rp.approveDevices {
		result.Add(RolePrivilege_ApproveDevice)
	}
	if rp.manageRecordTypes {
		result.Add(RolePrivilege_ManageRecordTypes)
	}
	if rp.sharingAdministrator {
		result.Add(RolePrivilege_SharingAdministrator)
	}
	if rp.runComplianceReport {
		result.Add(RolePrivilege_RunComplianceReports)
	}
	if rp.transferAccount {
		result.Add(RolePrivilege_TransferAccount)
	}
	if rp.manageCompanies {
		result.Add(RolePrivilege_ManageCompanies)
	}
	return
}
func (rp *rolePrivilege) SubjectUid() int64 {
	return rp.RoleId()
}
func (rp *rolePrivilege) ObjectUid() int64 {
	return rp.ManagedNodeId()
}
func (rp *rolePrivilege) SetManageNodes(value bool)          { rp.manageNodes = value }
func (rp *rolePrivilege) SetManageUsers(value bool)          { rp.manageUsers = value }
func (rp *rolePrivilege) SetManageRoles(value bool)          { rp.manageRoles = value }
func (rp *rolePrivilege) SetManageTeams(value bool)          { rp.manageTeams = value }
func (rp *rolePrivilege) SetRunReports(value bool)           { rp.runReports = value }
func (rp *rolePrivilege) SetManageBridge(value bool)         { rp.manageBridge = value }
func (rp *rolePrivilege) SetApproveDevices(value bool)       { rp.approveDevices = value }
func (rp *rolePrivilege) SetManageRecordTypes(value bool)    { rp.manageRecordTypes = value }
func (rp *rolePrivilege) SetSharingAdministrator(value bool) { rp.sharingAdministrator = value }
func (rp *rolePrivilege) SetRunComplianceReport(value bool)  { rp.runComplianceReport = value }
func (rp *rolePrivilege) SetTransferAccount(value bool)      { rp.transferAccount = value }
func (rp *rolePrivilege) SetManageCompanies(value bool)      { rp.manageCompanies = value }
func (rp *rolePrivilege) SetPrivilege(privilege string, value bool) {
	switch strings.ToUpper(privilege) {
	case RolePrivilege_ManageNodes:
		rp.SetManageNodes(value)
	case RolePrivilege_ManageUsers:
		rp.SetManageUsers(value)
	case RolePrivilege_ManageLicences:
		rp.manageLicenses = value
	case RolePrivilege_ManageRoles:
		rp.SetManageRoles(value)
	case RolePrivilege_ManageTeams:
		rp.SetManageTeams(value)
	case RolePrivilege_RunSecurityReports:
		rp.SetRunComplianceReport(value)
	case RolePrivilege_ManageBridge:
		rp.SetManageBridge(value)
	case RolePrivilege_ApproveDevice:
		rp.SetApproveDevices(value)
	case RolePrivilege_ManageRecordTypes:
		rp.SetManageRecordTypes(value)
	case RolePrivilege_RunComplianceReports:
		rp.SetRunComplianceReport(value)
	case RolePrivilege_ManageCompanies:
		rp.SetManageCompanies(value)
	case RolePrivilege_TransferAccount:
		rp.SetTransferAccount(value)
	case RolePrivilege_SharingAdministrator:
		rp.SetSharingAdministrator(value)
	}
}

type roleEnforcement struct {
	roleId          int64
	enforcementType string
	value           string
}

func (re *roleEnforcement) RoleId() int64 {
	return re.roleId
}
func (re *roleEnforcement) EnforcementType() string {
	return re.enforcementType
}
func (re *roleEnforcement) Value() string {
	return re.value
}
func (re *roleEnforcement) SubjectUid() int64 {
	return re.RoleId()
}
func (re *roleEnforcement) ObjectUid() string {
	return re.EnforcementType()
}
func (re *roleEnforcement) SetValue(value string) { re.value = value }

type userAlias struct {
	enterpriseUserId int64
	username         string
}

func (ua *userAlias) EnterpriseUserId() int64 {
	return ua.enterpriseUserId
}
func (ua *userAlias) Username() string {
	return ua.username
}
func (ua *userAlias) SubjectUid() int64 {
	return ua.EnterpriseUserId()
}
func (ua *userAlias) ObjectUid() string {
	return ua.Username()
}

type ssoService struct {
	ssoServiceProviderId int64
	nodeId               int64
	name                 string
	spUrl                string
	inviteNewUsers       bool
	active               bool
	isCloud              bool
}

func (s *ssoService) SsoServiceProviderId() int64 {
	return s.ssoServiceProviderId
}
func (s *ssoService) NodeId() int64 {
	return s.nodeId
}
func (s *ssoService) Name() string {
	return s.name
}
func (s *ssoService) SpUrl() string {
	return s.spUrl
}
func (s *ssoService) InviteNewUsers() bool {
	return s.inviteNewUsers
}
func (s *ssoService) Active() bool {
	return s.active
}
func (s *ssoService) IsCloud() bool {
	return s.isCloud
}
func (s *ssoService) Uid() int64 {
	return s.SsoServiceProviderId()
}

type bridge struct {
	bridgeId         int64
	nodeId           int64
	wanIpEnforcement string
	lanIpEnforcement string
	status           string
}

func (b *bridge) BridgeId() int64 {
	return b.bridgeId
}
func (b *bridge) NodeId() int64 {
	return b.nodeId
}
func (b *bridge) WanIpEnforcement() string {
	return b.wanIpEnforcement
}
func (b *bridge) LanIpEnforcement() string {
	return b.lanIpEnforcement
}
func (b *bridge) Status() string {
	return b.status
}
func (b *bridge) Uid() int64 {
	return b.BridgeId()
}

type scim struct {
	scimId       int64
	nodeId       int64
	status       string
	lastSynced   int64
	rolePrefix   string
	uniqueGroups bool
}

func (sc *scim) ScimId() int64 {
	return sc.scimId
}
func (sc *scim) NodeId() int64 {
	return sc.nodeId
}
func (sc *scim) Status() string {
	return sc.status
}
func (sc *scim) LastSynced() int64 {
	return sc.lastSynced
}
func (sc *scim) RolePrefix() string {
	return sc.rolePrefix
}
func (sc *scim) UniqueGroups() bool {
	return sc.uniqueGroups
}
func (sc *scim) Uid() int64 {
	return sc.ScimId()
}

type emailProvision struct {
	id     int32
	nodeId int64
	domain string
	method string
}

func (e *emailProvision) Id() int64 {
	return int64(e.id)
}
func (e *emailProvision) NodeId() int64 {
	return e.nodeId
}
func (e *emailProvision) Domain() string {
	return e.domain
}
func (e *emailProvision) Method() string {
	return e.method
}
func (e *emailProvision) Uid() int64 {
	return e.Id()
}

type managedCompany struct {
	mcEnterpriseId   int32
	mcEnterpriseName string
	mspNodeId        int64
	numberOfSeats    int32
	numberOfUsers    int32
	productId        string
	isExpired        bool
	treeKey          string
	treeKeyRole      int64
	filePlanType     string
	addOns           []ILicenseAddOn
}

func (mc *managedCompany) McEnterpriseId() int64 {
	return int64(mc.mcEnterpriseId)
}
func (mc *managedCompany) McEnterpriseName() string {
	return mc.mcEnterpriseName
}
func (mc *managedCompany) MspNodeId() int64 {
	return mc.mspNodeId
}
func (mc *managedCompany) NumberOfSeats() int32 {
	return mc.numberOfSeats
}
func (mc *managedCompany) NumberOfUsers() int32 {
	return mc.numberOfUsers
}
func (mc *managedCompany) ProductId() string {
	return mc.productId
}
func (mc *managedCompany) IsExpired() bool {
	return mc.isExpired
}
func (mc *managedCompany) TreeKey() string {
	return mc.treeKey
}
func (mc *managedCompany) TreeKeyRole() int64 {
	return mc.treeKeyRole
}
func (mc *managedCompany) FilePlanType() string {
	return mc.filePlanType
}
func (mc *managedCompany) AddOns() []ILicenseAddOn {
	return mc.addOns
}
func (mc *managedCompany) Uid() int64 {
	return mc.McEnterpriseId()
}

type queuedTeam struct {
	teamUid       string
	name          string
	nodeId        int64
	encryptedData string
}

func (qt *queuedTeam) TeamUid() string {
	return qt.teamUid
}
func (qt *queuedTeam) Name() string {
	return qt.name
}
func (qt *queuedTeam) NodeId() int64 {
	return qt.nodeId
}
func (qt *queuedTeam) EncryptedData() string {
	return qt.encryptedData
}
func (qt *queuedTeam) Uid() string {
	return qt.TeamUid()
}

type queuedTeamUser struct {
	teamUid          string
	enterpriseUserId int64
}

func (qtu *queuedTeamUser) TeamUid() string {
	return qtu.teamUid
}
func (qtu *queuedTeamUser) EnterpriseUserId() int64 {
	return qtu.enterpriseUserId
}
func (qtu *queuedTeamUser) SubjectUid() string {
	return qtu.TeamUid()
}
func (qtu *queuedTeamUser) ObjectUid() int64 {
	return qtu.EnterpriseUserId()
}
