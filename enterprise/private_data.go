package enterprise

import (
	"crypto/ecdh"
	"crypto/rsa"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_enterprise"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	"github.com/keeper-security/keeper-sdk-golang/vault"
	"go.uber.org/zap"
	"strconv"
	"strings"
)

var allEnforcements map[string]string

func init() {
	allEnforcements = make(map[string]string)
	AvailableRoleEnforcements(func(x IEnforcement) bool {
		allEnforcements[strings.ToLower(x.Name())] = strings.ToLower(x.ValueType())
		return true
	})
}

type iLicenseEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[ILicense, int64]
}
type iNodeEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[INode, int64]
}

type iRoleEntity interface {
	iEnterprisePlugin
	iEnterpriseEntityPlugin[int64]
	IEnterpriseEntity[IRole, int64]
}

type iUserEntity interface {
	iEnterprisePlugin
	iEnterpriseEntityPlugin[int64]
	IEnterpriseEntity[IUser, int64]
}

type iTeamEntity interface {
	iEnterprisePlugin
	iEnterpriseEntityPlugin[string]
	IEnterpriseEntity[ITeam, string]
}

type iTeamUserLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[string, int64]
	IEnterpriseLink[ITeamUser, string, int64]
}

type iQueuedTeamEntity interface {
	iEnterprisePlugin
	iEnterpriseEntityPlugin[string]
	IEnterpriseEntity[IQueuedTeam, string]
}

type iQueuedTeamUserLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[string, int64]
	IEnterpriseLink[IQueuedTeamUser, string, int64]
}

type iRoleUserLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[int64, int64]
	IEnterpriseLink[IRoleUser, int64, int64]
}

type iRoleTeamLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[int64, string]
	IEnterpriseLink[IRoleTeam, int64, string]
}

type iManagedNodeLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[int64, int64]
	IEnterpriseLink[IManagedNode, int64, int64]
}

type iRolePrivilegeLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[int64, int64]
	IEnterpriseLink[IRolePrivilege, int64, int64]
}

type iRoleEnforcementLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[int64, string]
	IEnterpriseLink[IRoleEnforcement, int64, string]
}

type iUserAliasLink interface {
	iEnterprisePlugin
	iEnterpriseLinkPlugin[int64, string]
	IEnterpriseLink[IUserAlias, int64, string]
}

type iSsoServiceEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[ISsoService, int64]
}

type iBridgeEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[IBridge, int64]
}

type iScimEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[IScim, int64]
}

type iEmailProvisionEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[IEmailProvision, int64]
}

type iManagedCompanyEntity interface {
	iEnterprisePlugin
	IEnterpriseEntity[IManagedCompany, int64]
}

func newLicenseEntity() iLicenseEntity {
	return &baseEntity[proto_enterprise.License, ILicense, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.License, ILicense, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.License, treeKey []byte) (k int64, l ILicense) {
				k = protoEntity.EnterpriseLicenseId
				if treeKey != nil {
					var ll = &license{
						enterpriseLicenseId: protoEntity.EnterpriseLicenseId,
						licenseKeyId:        protoEntity.LicenseKeyId,
						productTypeId:       protoEntity.ProductTypeId,
						filePlanId:          protoEntity.FilePlanTypeId,
						name:                protoEntity.Name,
						numberOfSeats:       protoEntity.NumberOfSeats,
						seatsAllocated:      protoEntity.SeatsAllocated,
						seatsPending:        protoEntity.SeatsPending,
						licenseStatus:       protoEntity.LicenseStatus,
						nextBillingDate:     protoEntity.NextBillingDate,
						expiration:          protoEntity.Expiration,
						storageExpiration:   protoEntity.StorageExpiration,
						distributor:         protoEntity.Distributor,
					}
					for _, ao := range protoEntity.AddOns {
						var lao = &licenseAddOn{
							name:              ao.Name,
							enabled:           ao.Enabled,
							includedInProduct: ao.IncludedInProduct,
							isTrial:           ao.IsTrial,
							seats:             ao.Seats,
							apiCallCount:      ao.ApiCallCount,
							created:           ao.Created,
							activationTime:    ao.ActivationTime,
							expiration:        ao.Expiration,
						}
						ll.addOns = append(ll.addOns, lao)
					}
					if ll.distributor && ll.mspPermits != nil {
						var mspp = &mspPermits{
							restricted:             protoEntity.MspPermits.Restricted,
							maxFilePlanType:        protoEntity.MspPermits.MaxFilePlanType,
							allowUnlimitedLicenses: protoEntity.MspPermits.AllowUnlimitedLicenses,
							allowedMcProducts:      protoEntity.MspPermits.AllowedMcProducts,
							allowedAddOns:          protoEntity.MspPermits.AllowedAddOns,
						}
						for _, x := range protoEntity.MspPermits.McDefaults {
							var md = &mcDefaults{
								mcProduct:        x.McProduct,
								filePlanType:     x.FilePlanType,
								maxLicenses:      x.MaxLicenses,
								addons:           x.AddOns,
								fixedMaxLicenses: x.FixedMaxLicenses,
							}
							mspp.mcDefaults = append(mspp.mcDefaults, md)
						}
					}
					if protoEntity.ManagedBy != nil && protoEntity.ManagedBy.EnterpriseId > 0 {
						ll.managedBy = &mspContact{
							enterpriseId:   protoEntity.ManagedBy.EnterpriseId,
							enterpriseName: protoEntity.ManagedBy.EnterpriseName,
						}
					}
					l = ll
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.License) string {
				return strconv.FormatInt(protoEntity.EnterpriseLicenseId, 16)
			},
		},
	}
}

func newNodeEntity() iNodeEntity {
	return &baseEntity[proto_enterprise.Node, INode, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.Node, INode, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.Node, treeKey []byte) (k int64, n INode) {
				k = protoEntity.NodeId
				if treeKey != nil {
					var name string
					var encData *database.EncryptedData
					var er1 error
					if encData, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
						name = encData.DisplayName
					} else {
						api.GetLogger().Debug("Parse Node encrypted data", zap.Error(er1),
							zap.Int64("nodeId", protoEntity.NodeId))
					}
					if len(name) == 0 {
						name = strconv.FormatInt(protoEntity.NodeId, 16)
					}
					n = &node{
						nodeId:               protoEntity.NodeId,
						name:                 name,
						parentId:             protoEntity.ParentId,
						bridgeId:             protoEntity.BridgeId,
						scimId:               protoEntity.ScimId,
						licenseId:            protoEntity.LicenseId,
						duoEnabled:           protoEntity.DuoEnabled,
						rsaEnabled:           protoEntity.RsaEnabled,
						ssoServiceProviderId: protoEntity.SsoServiceProviderIds[:],
						encryptedData:        protoEntity.GetEncryptedData(),
					}

				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.Node) string {
				return strconv.FormatInt(protoEntity.NodeId, 16)
			},
		},
	}
}

func newRoleEntity() iRoleEntity {
	return &baseEntity[proto_enterprise.Role, IRole, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.Role, IRole, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.Role, treeKey []byte) (k int64, r IRole) {
				k = protoEntity.RoleId
				if treeKey != nil {
					var name string
					var encData *database.EncryptedData
					var er1 error
					if encData, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
						name = encData.DisplayName
					} else {
						api.GetLogger().Debug("Parse Role encrypted data", zap.Error(er1),
							zap.Int64("roleId", protoEntity.RoleId))
					}
					if len(name) == 0 {
						name = strconv.FormatInt(protoEntity.RoleId, 16)
					}
					r = &role{
						roleId:         protoEntity.RoleId,
						name:           name,
						nodeId:         protoEntity.NodeId,
						keyType:        protoEntity.KeyType,
						visibleBelow:   protoEntity.VisibleBelow,
						newUserInherit: protoEntity.NewUserInherit,
						roleType:       protoEntity.RoleType,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.Role) string {
				return strconv.FormatInt(protoEntity.RoleId, 16)
			},
		},
	}
}

func newUserEntity() iUserEntity {
	return &baseEntity[proto_enterprise.User, IUser, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.User, IUser, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.User, treeKey []byte) (k int64, u IUser) {
				k = protoEntity.EnterpriseUserId
				if treeKey != nil {
					var fullName string
					if len(protoEntity.EncryptedData) > 0 {
						if strings.EqualFold(protoEntity.KeyType, "no_key") {
							fullName = protoEntity.EncryptedData
						} else {
							var encData *database.EncryptedData
							var er1 error
							var name string
							if encData, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 == nil {
								name = encData.DisplayName
								if len(name) > 0 {
									fullName = name
								}
							} else {
								api.GetLogger().Debug("Parse User encrypted data", zap.Error(er1),
									zap.Int64("userId", protoEntity.EnterpriseUserId))
							}
						}
					}
					u = &user{
						enterpriseUserId:         protoEntity.EnterpriseUserId,
						username:                 protoEntity.Username,
						fullName:                 fullName,
						jobTitle:                 protoEntity.JobTitle,
						nodeId:                   protoEntity.NodeId,
						status:                   UserStatus(protoEntity.Status),
						lock:                     UserLock(protoEntity.Lock),
						userId:                   protoEntity.UserId,
						accountShareExpiration:   protoEntity.AccountShareExpiration,
						tfaEnabled:               protoEntity.TfaEnabled,
						transferAcceptanceStatus: int32(protoEntity.TransferAcceptanceStatus),
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.User) string {
				return strconv.FormatInt(protoEntity.EnterpriseUserId, 16)
			},
		},
	}
}

func newQueuedTeamEntity() iQueuedTeamEntity {
	return &baseEntity[proto_enterprise.QueuedTeam, IQueuedTeam, string]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.QueuedTeam, IQueuedTeam, string]{
			onConvertEntity: func(protoEntity *proto_enterprise.QueuedTeam, treeKey []byte) (k string, qt IQueuedTeam) {
				k = api.Base64UrlEncode(protoEntity.TeamUid)
				if treeKey != nil {
					qt = &queuedTeam{
						teamUid:       api.Base64UrlEncode(protoEntity.TeamUid),
						name:          protoEntity.Name,
						nodeId:        protoEntity.NodeId,
						encryptedData: protoEntity.EncryptedData,
					}
					if len(protoEntity.EncryptedData) > 0 {
						var er1 error
						if _, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 != nil {
							api.GetLogger().Debug("Parse Team encrypted data", zap.Error(er1),
								zap.String("teamUid", api.Base64UrlEncode(protoEntity.TeamUid)))
						}
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.QueuedTeam) string {
				return api.Base64UrlEncode(protoEntity.TeamUid)
			},
		},
	}
}

func newTeamEntity() iTeamEntity {
	return &baseEntity[proto_enterprise.Team, ITeam, string]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.Team, ITeam, string]{
			onConvertEntity: func(protoEntity *proto_enterprise.Team, treeKey []byte) (k string, t ITeam) {
				k = api.Base64UrlEncode(protoEntity.TeamUid)
				if treeKey != nil {
					t = &team{
						teamUid:          api.Base64UrlEncode(protoEntity.TeamUid),
						name:             protoEntity.Name,
						nodeId:           protoEntity.NodeId,
						restrictEdit:     protoEntity.RestrictEdit,
						restrictShare:    protoEntity.RestrictShare,
						restrictView:     protoEntity.RestrictView,
						encryptedTeamKey: api.Base64UrlDecode(protoEntity.EncryptedTeamKey),
					}
					if len(protoEntity.EncryptedData) > 0 {
						var er1 error
						if _, er1 = parseEncryptedData(protoEntity.EncryptedData, treeKey); er1 != nil {
							api.GetLogger().Debug("Parse Team encrypted data", zap.Error(er1),
								zap.String("teamUid", api.Base64UrlEncode(protoEntity.TeamUid)))
						}
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.Team) string {
				return api.Base64UrlEncode(protoEntity.TeamUid)
			},
		},
	}
}

func newSsoServiceEntity() iSsoServiceEntity {
	return &baseEntity[proto_enterprise.SsoService, ISsoService, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.SsoService, ISsoService, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.SsoService, treeKey []byte) (k int64, sso ISsoService) {
				k = protoEntity.SsoServiceProviderId
				if treeKey != nil {
					sso = &ssoService{
						ssoServiceProviderId: protoEntity.SsoServiceProviderId,
						nodeId:               protoEntity.NodeId,
						name:                 protoEntity.Name,
						spUrl:                protoEntity.SpUrl,
						inviteNewUsers:       protoEntity.InviteNewUsers,
						active:               protoEntity.Active,
						isCloud:              protoEntity.IsCloud,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.SsoService) string {
				return strconv.FormatInt(protoEntity.SsoServiceProviderId, 16)
			},
		},
	}
}

func newBridgeEntity() iBridgeEntity {
	return &baseEntity[proto_enterprise.Bridge, IBridge, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.Bridge, IBridge, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.Bridge, treeKey []byte) (k int64, b IBridge) {
				k = protoEntity.BridgeId
				if treeKey != nil {
					b = &bridge{
						bridgeId:         protoEntity.BridgeId,
						nodeId:           protoEntity.NodeId,
						wanIpEnforcement: protoEntity.WanIpEnforcement,
						lanIpEnforcement: protoEntity.LanIpEnforcement,
						status:           protoEntity.Status,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.Bridge) string {
				return strconv.FormatInt(protoEntity.BridgeId, 16)
			},
		},
	}
}

func newScimEntity() iScimEntity {
	return &baseEntity[proto_enterprise.Scim, IScim, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.Scim, IScim, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.Scim, treeKey []byte) (k int64, sc IScim) {
				k = protoEntity.ScimId
				if treeKey != nil {
					sc = &scim{
						scimId:       protoEntity.ScimId,
						nodeId:       protoEntity.NodeId,
						status:       protoEntity.Status,
						lastSynced:   protoEntity.LastSynced,
						rolePrefix:   protoEntity.RolePrefix,
						uniqueGroups: protoEntity.UniqueGroups,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.Scim) string {
				return strconv.FormatInt(protoEntity.ScimId, 16)
			},
		},
	}
}

func newEmailProvisionEntity() iEmailProvisionEntity {
	return &baseEntity[proto_enterprise.EmailProvision, IEmailProvision, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.EmailProvision, IEmailProvision, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.EmailProvision, treeKey []byte) (k int64, ep IEmailProvision) {
				k = int64(protoEntity.Id)
				if treeKey != nil {
					ep = &emailProvision{
						id:     protoEntity.Id,
						nodeId: protoEntity.NodeId,
						domain: protoEntity.Domain,
						method: protoEntity.Method,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.EmailProvision) string {
				return strconv.FormatInt(int64(protoEntity.Id), 16)
			},
		},
	}
}

func newManagedCompanyEntity() iManagedCompanyEntity {
	return &baseEntity[proto_enterprise.ManagedCompany, IManagedCompany, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.ManagedCompany, IManagedCompany, int64]{
			onConvertEntity: func(protoEntity *proto_enterprise.ManagedCompany, treeKey []byte) (k int64, mc IManagedCompany) {
				k = int64(protoEntity.McEnterpriseId)
				if treeKey != nil {
					var m = &managedCompany{
						mcEnterpriseId:   protoEntity.McEnterpriseId,
						mcEnterpriseName: protoEntity.McEnterpriseName,
						mspNodeId:        protoEntity.MspNodeId,
						numberOfSeats:    protoEntity.NumberOfSeats,
						numberOfUsers:    protoEntity.NumberOfUsers,
						productId:        protoEntity.ProductId,
						isExpired:        protoEntity.IsExpired,
						treeKey:          protoEntity.TreeKey,
						treeKeyRole:      protoEntity.TreeKeyRole,
						filePlanType:     protoEntity.FilePlanType,
					}
					for _, x := range protoEntity.AddOns {
						var ao = &licenseAddOn{
							name:              x.Name,
							enabled:           x.Enabled,
							includedInProduct: x.IncludedInProduct,
							isTrial:           x.IsTrial,
							seats:             x.Seats,
							apiCallCount:      x.ApiCallCount,
							created:           x.Created,
							activationTime:    x.ActivationTime,
							expiration:        x.Expiration,
						}
						m.addOns = append(m.addOns, ao)
					}
					mc = m
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.ManagedCompany) string {
				return strconv.FormatInt(int64(protoEntity.McEnterpriseId), 16)
			},
		},
	}
}

func newTeamUserLink() iTeamUserLink {
	return &baseLink[proto_enterprise.TeamUser, ITeamUser, string, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.TeamUser, ITeamUser, LinkKey[string, int64]]{
			onConvertEntity: func(protoEntity *proto_enterprise.TeamUser, treeKey []byte) (k LinkKey[string, int64], tu ITeamUser) {
				k.V1 = api.Base64UrlEncode(protoEntity.TeamUid)
				k.V2 = protoEntity.EnterpriseUserId
				if treeKey != nil {
					tu = &teamUser{
						teamUid:          api.Base64UrlEncode(protoEntity.TeamUid),
						enterpriseUserId: protoEntity.EnterpriseUserId,
						userType:         protoEntity.UserType,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.TeamUser) string {
				return strings.Join([]string{
					api.Base64UrlEncode(protoEntity.TeamUid),
					strconv.FormatInt(protoEntity.EnterpriseUserId, 16)}, "|")
			},
		},
	}
}

func newRoleUserLink() iRoleUserLink {
	return &baseLink[proto_enterprise.RoleUser, IRoleUser, int64, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.RoleUser, IRoleUser, LinkKey[int64, int64]]{
			onConvertEntity: func(protoEntity *proto_enterprise.RoleUser, treeKey []byte) (k LinkKey[int64, int64], ru IRoleUser) {
				k.V1 = protoEntity.RoleId
				k.V2 = protoEntity.EnterpriseUserId
				if treeKey != nil {
					ru = &roleUser{
						roleId:           protoEntity.RoleId,
						enterpriseUserId: protoEntity.EnterpriseUserId,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.RoleUser) string {
				return strings.Join([]string{
					strconv.FormatInt(protoEntity.RoleId, 16),
					strconv.FormatInt(protoEntity.EnterpriseUserId, 16)}, "|")
			},
		},
	}
}

func newRoleTeamLink() iRoleTeamLink {
	return &baseLink[proto_enterprise.RoleTeam, IRoleTeam, int64, string]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.RoleTeam, IRoleTeam, LinkKey[int64, string]]{
			onConvertEntity: func(protoEntity *proto_enterprise.RoleTeam, treeKey []byte) (k LinkKey[int64, string], rt IRoleTeam) {
				k.V1 = protoEntity.RoleId
				k.V2 = api.Base64UrlEncode(protoEntity.TeamUid)
				if treeKey != nil {
					rt = &roleTeam{
						roleId:  protoEntity.RoleId,
						teamUid: api.Base64UrlEncode(protoEntity.TeamUid),
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.RoleTeam) string {
				return strings.Join([]string{
					strconv.FormatInt(protoEntity.RoleId, 16),
					api.Base64UrlEncode(protoEntity.TeamUid)}, "|")
			},
		},
	}
}

func newUserAliasLink() iUserAliasLink {
	return &baseLink[proto_enterprise.UserAlias, IUserAlias, int64, string]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.UserAlias, IUserAlias, LinkKey[int64, string]]{
			onConvertEntity: func(protoEntity *proto_enterprise.UserAlias, treeKey []byte) (k LinkKey[int64, string], ua IUserAlias) {
				k.V1 = protoEntity.EnterpriseUserId
				k.V2 = protoEntity.Username
				if treeKey != nil {
					ua = &userAlias{
						enterpriseUserId: protoEntity.EnterpriseUserId,
						username:         protoEntity.Username,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.UserAlias) string {
				return strings.Join([]string{
					strconv.FormatInt(protoEntity.EnterpriseUserId, 16),
					protoEntity.Username}, "|")
			},
		},
	}
}

func newManagedNodeLink() iManagedNodeLink {
	return &baseLink[proto_enterprise.ManagedNode, IManagedNode, int64, int64]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.ManagedNode, IManagedNode, LinkKey[int64, int64]]{
			onConvertEntity: func(protoEntity *proto_enterprise.ManagedNode, treeKey []byte) (k LinkKey[int64, int64], mn IManagedNode) {
				k.V1 = protoEntity.RoleId
				k.V2 = protoEntity.ManagedNodeId
				if treeKey != nil {
					mn = &managedNode{
						roleId:                protoEntity.RoleId,
						managedNodeId:         protoEntity.ManagedNodeId,
						cascadeNodeManagement: protoEntity.CascadeNodeManagement,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.ManagedNode) string {
				return strings.Join([]string{
					strconv.FormatInt(protoEntity.RoleId, 16),
					strconv.FormatInt(protoEntity.ManagedNodeId, 16)}, "|")
			},
		},
	}
}

func newQueuedTeamUserLink() iQueuedTeamUserLink {
	return &baseLink[proto_enterprise.QueuedTeamUser, IQueuedTeamUser, string, int64]{
		iEntityConversion: &multipleEntityConversion[proto_enterprise.QueuedTeamUser, IQueuedTeamUser, LinkKey[string, int64]]{
			onConvertEntityFunc: func(protoEntity *proto_enterprise.QueuedTeamUser, treeKey []byte, cb func(LinkKey[string, int64], IQueuedTeamUser)) {
				var teamUid = api.Base64UrlEncode(protoEntity.TeamUid)
				for _, x := range protoEntity.Users {
					var lk = LinkKey[string, int64]{
						V1: teamUid,
						V2: x,
					}
					var qtu IQueuedTeamUser
					if treeKey != nil {
						qtu = &queuedTeamUser{
							teamUid:          teamUid,
							enterpriseUserId: x,
						}
					}
					cb(lk, qtu)
				}
			},
			onStorageKey: func(protoEntity *proto_enterprise.QueuedTeamUser) string {
				return api.Base64UrlEncode(protoEntity.TeamUid)
			},
		},
	}
}

func newRoleEnforcementLink() iRoleEnforcementLink {
	return &baseLink[proto_enterprise.RoleEnforcement, IRoleEnforcement, int64, string]{
		iEntityConversion: &singleEntityConversion[proto_enterprise.RoleEnforcement, IRoleEnforcement, LinkKey[int64, string]]{
			onConvertEntity: func(protoEntity *proto_enterprise.RoleEnforcement, treeKey []byte) (k LinkKey[int64, string], re IRoleEnforcement) {
				k.V1 = protoEntity.RoleId
				k.V2 = strings.ToLower(protoEntity.EnforcementType)
				if treeKey != nil {
					var eType = strings.ToLower(protoEntity.EnforcementType)
					var eValue = protoEntity.Value
					if len(eValue) == 0 {
						var vType string
						var ok bool
						if vType, ok = allEnforcements[eType]; ok {
							switch vType {
							case "bool":
								eValue = "true"
							}
						}
					}
					re = &roleEnforcement{
						roleId:          protoEntity.RoleId,
						enforcementType: eType,
						value:           eValue,
					}
				}
				return
			},
			onStorageKey: func(protoEntity *proto_enterprise.RoleEnforcement) string {
				return strings.Join([]string{
					strconv.FormatInt(protoEntity.RoleId, 16),
					strings.ToUpper(protoEntity.EnforcementType)}, "|")
			},
		},
	}
}

type rolePrivilegeLink struct {
	data map[LinkKey[int64, int64]]*rolePrivilege
}

func (rpl *rolePrivilegeLink) store(data []byte, _ []byte) (primaryKey string, err error) {
	var rpp *proto_enterprise.RolePrivilege
	if rpp, err = newEntity[proto_enterprise.RolePrivilege](data); err != nil {
		return
	}
	if rpl.data == nil {
		rpl.data = make(map[LinkKey[int64, int64]]*rolePrivilege)
	}
	var lk = LinkKey[int64, int64]{
		V1: rpp.RoleId,
		V2: rpp.ManagedNodeId,
	}
	var ok bool
	var rp *rolePrivilege
	if rp, ok = rpl.data[lk]; !ok {
		rp = &rolePrivilege{
			roleId:        rpp.RoleId,
			managedNodeId: rpp.ManagedNodeId,
		}
		rpl.data[lk] = rp
	}
	rp.SetPrivilege(rpp.PrivilegeType, true)
	primaryKey = fmt.Sprintf("%d|%d|%s", rpp.RoleId, rpp.ManagedNodeId, rpp.PrivilegeType)
	return
}
func (rpl *rolePrivilegeLink) delete(data []byte) (primaryKey string, err error) {
	var rpp *proto_enterprise.RolePrivilege
	if rpp, err = newEntity[proto_enterprise.RolePrivilege](data); err != nil {
		return
	}
	if rpl.data != nil {
		var lk = LinkKey[int64, int64]{
			V1: rpp.RoleId,
			V2: rpp.ManagedNodeId,
		}
		var ok bool
		var rp *rolePrivilege
		if rp, ok = rpl.data[lk]; ok {
			rp.SetPrivilege(rpp.PrivilegeType, false)
		}
	}
	primaryKey = fmt.Sprintf("%d|%d|%s", rpp.RoleId, rpp.ManagedNodeId, rpp.PrivilegeType)
	return
}
func (rpl *rolePrivilegeLink) clear() {
	rpl.data = nil
}
func (rpl *rolePrivilegeLink) enumerateData(cmp func(key LinkKey[int64, int64]) bool, cb func(IRolePrivilege) bool) {
	if rpl.data == nil {
		return
	}
	for k, v := range rpl.data {
		if !cmp(k) {
			continue
		}
		if cb != nil {
			if !cb(v) {
				break
			}
		}
	}
}

func (rpl *rolePrivilegeLink) GetAllLinks(cb func(IRolePrivilege) bool) {
	rpl.enumerateData(
		func(key LinkKey[int64, int64]) bool { return true },
		func(privilege IRolePrivilege) bool { return cb(privilege) })
}
func (rpl *rolePrivilegeLink) GetLink(roleId int64, nodeId int64) (result IRolePrivilege) {
	rpl.enumerateData(
		func(key LinkKey[int64, int64]) bool { return key.V1 == roleId && key.V2 == nodeId },
		func(privilege IRolePrivilege) bool {
			result = privilege
			return false
		})
	return
}
func (rpl *rolePrivilegeLink) GetLinksBySubject(roleId int64, cb func(IRolePrivilege) bool) {
	rpl.enumerateData(
		func(key LinkKey[int64, int64]) bool { return key.V1 == roleId },
		func(privilege IRolePrivilege) bool { return cb(privilege) })
}

func (rpl *rolePrivilegeLink) GetLinksByObject(nodeId int64, cb func(IRolePrivilege) bool) {
	rpl.enumerateData(
		func(key LinkKey[int64, int64]) bool { return key.V2 == nodeId },
		func(privilege IRolePrivilege) bool { return cb(privilege) })
}
func (rpl *rolePrivilegeLink) deleteBySubject(roleId int64) {
	if rpl.data == nil {
		return
	}
	if rpl.data != nil {
		var links []LinkKey[int64, int64]
		for k := range rpl.data {
			if k.V1 == roleId {
				links = append(links, k)
			}
		}
		for _, k := range links {
			delete(rpl.data, k)
		}
	}
}
func (rpl *rolePrivilegeLink) deleteByObject(nodeId int64) {
	if rpl.data == nil {
		return
	}
	if rpl.data != nil {
		var links []LinkKey[int64, int64]
		for k := range rpl.data {
			if k.V2 == nodeId {
				links = append(links, k)
			}
		}
		for _, k := range links {
			delete(rpl.data, k)
		}
	}
}

func newRolePrivileges() iRolePrivilegeLink {
	return new(rolePrivilegeLink)
}

type enterpriseInfo struct {
	enterpriseName string
	treeKey        []byte
	rsaPrivateKey  *rsa.PrivateKey
	ecPrivateKey   *ecdh.PrivateKey
	isDistributor  bool
}

func (ei *enterpriseInfo) IsDistributor() bool {
	return ei.isDistributor
}
func (ei *enterpriseInfo) EnterpriseName() string {
	return ei.enterpriseName
}
func (ei *enterpriseInfo) TreeKey() []byte {
	return ei.treeKey
}
func (ei *enterpriseInfo) RsaPrivateKey() *rsa.PrivateKey {
	return ei.rsaPrivateKey
}
func (ei *enterpriseInfo) EcPrivateKey() *ecdh.PrivateKey {
	return ei.ecPrivateKey
}

type iEnterprisePlugin interface {
	store(data []byte, encryptionKey []byte) (primaryKey string, err error)
	delete(data []byte) (primaryKey string, err error)
	clear()
}

type iEnterpriseEntityPlugin[K storage.Key] interface {
	registerCascadeDelete(func(K))
}

type iEnterpriseLinkPlugin[KS storage.Key, KO storage.Key] interface {
	deleteBySubject(KS)
	deleteByObject(KO)
}

type enterpriseData struct {
	enterpriseInfo   *enterpriseInfo
	nodes            iNodeEntity
	roles            iRoleEntity
	users            iUserEntity
	teams            iTeamEntity
	teamUsers        iTeamUserLink
	queuedTeams      iQueuedTeamEntity
	queuedTeamUsers  iQueuedTeamUserLink
	roleUsers        iRoleUserLink
	roleTeams        iRoleTeamLink
	roleEnforcements iRoleEnforcementLink
	managedNodes     iManagedNodeLink
	rolePrivileges   iRolePrivilegeLink
	licenses         iLicenseEntity
	userAliases      iUserAliasLink
	ssoServices      iSsoServiceEntity
	bridges          iBridgeEntity
	scims            iScimEntity
	emailProvisions  iEmailProvisionEntity
	managedCompanies iManagedCompanyEntity
	rootNode         INode
	recordTypes      enterpriseEntity[vault.IRecordType, string]
}

func (ed *enterpriseData) RootNode() INode {
	return ed.rootNode
}

func (ed *enterpriseData) EnterpriseInfo() IEnterpriseInfo {
	return ed.enterpriseInfo
}

func (ed *enterpriseData) getSupportedEntities() (res []proto_enterprise.EnterpriseDataEntity) {
	res = append(res, proto_enterprise.EnterpriseDataEntity_NODES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_ROLES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_USERS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_TEAMS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_TEAM_USERS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_QUEUED_TEAMS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_QUEUED_TEAM_USERS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_ROLE_USERS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_ROLE_TEAMS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_ROLE_PRIVILEGES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_MANAGED_NODES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_LICENSES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_USER_ALIASES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_SSO_SERVICES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_BRIDGES)
	res = append(res, proto_enterprise.EnterpriseDataEntity_SCIMS)
	res = append(res, proto_enterprise.EnterpriseDataEntity_EMAIL_PROVISION)
	return
}

func (ed *enterpriseData) getEnterprisePlugin(entityType proto_enterprise.EnterpriseDataEntity) (plugin iEnterprisePlugin) {
	switch entityType {
	case proto_enterprise.EnterpriseDataEntity_LICENSES:
		return ed.licenses
	case proto_enterprise.EnterpriseDataEntity_NODES:
		return ed.nodes
	case proto_enterprise.EnterpriseDataEntity_ROLES:
		return ed.roles
	case proto_enterprise.EnterpriseDataEntity_USERS:
		return ed.users
	case proto_enterprise.EnterpriseDataEntity_TEAMS:
		return ed.teams
	case proto_enterprise.EnterpriseDataEntity_TEAM_USERS:
		return ed.teamUsers
	case proto_enterprise.EnterpriseDataEntity_QUEUED_TEAMS:
		return ed.queuedTeams
	case proto_enterprise.EnterpriseDataEntity_QUEUED_TEAM_USERS:
		return ed.queuedTeamUsers
	case proto_enterprise.EnterpriseDataEntity_ROLE_USERS:
		return ed.roleUsers
	case proto_enterprise.EnterpriseDataEntity_ROLE_TEAMS:
		return ed.roleTeams
	case proto_enterprise.EnterpriseDataEntity_ROLE_ENFORCEMENTS:
		return ed.roleEnforcements
	case proto_enterprise.EnterpriseDataEntity_ROLE_PRIVILEGES:
		return ed.rolePrivileges
	case proto_enterprise.EnterpriseDataEntity_MANAGED_NODES:
		return ed.managedNodes
	case proto_enterprise.EnterpriseDataEntity_USER_ALIASES:
		return ed.userAliases
	case proto_enterprise.EnterpriseDataEntity_SSO_SERVICES:
		return ed.ssoServices
	case proto_enterprise.EnterpriseDataEntity_BRIDGES:
		return ed.bridges
	case proto_enterprise.EnterpriseDataEntity_SCIMS:
		return ed.scims
	case proto_enterprise.EnterpriseDataEntity_EMAIL_PROVISION:
		return ed.emailProvisions
	case proto_enterprise.EnterpriseDataEntity_MANAGED_COMPANIES:
		return ed.managedCompanies
	}
	api.GetLogger().Debug("Enterprise entity is not supported.", zap.String("entity", entityType.String()))
	return
}

func (ed *enterpriseData) Licenses() IEnterpriseEntity[ILicense, int64] {
	return ed.licenses
}
func (ed *enterpriseData) Nodes() IEnterpriseEntity[INode, int64] {
	return ed.nodes
}
func (ed *enterpriseData) Roles() IEnterpriseEntity[IRole, int64] {
	return ed.roles
}
func (ed *enterpriseData) Users() IEnterpriseEntity[IUser, int64] {
	return ed.users
}
func (ed *enterpriseData) Teams() IEnterpriseEntity[ITeam, string] {
	return ed.teams
}
func (ed *enterpriseData) TeamUsers() IEnterpriseLink[ITeamUser, string, int64] {
	return ed.teamUsers
}
func (ed *enterpriseData) QueuedTeams() IEnterpriseEntity[IQueuedTeam, string] {
	return ed.queuedTeams
}
func (ed *enterpriseData) QueuedTeamUsers() IEnterpriseLink[IQueuedTeamUser, string, int64] {
	return ed.queuedTeamUsers
}
func (ed *enterpriseData) RoleUsers() IEnterpriseLink[IRoleUser, int64, int64] {
	return ed.roleUsers
}
func (ed *enterpriseData) RoleTeams() IEnterpriseLink[IRoleTeam, int64, string] {
	return ed.roleTeams
}
func (ed *enterpriseData) RoleEnforcements() IEnterpriseLink[IRoleEnforcement, int64, string] {
	return ed.roleEnforcements
}
func (ed *enterpriseData) RolePrivileges() IEnterpriseLink[IRolePrivilege, int64, int64] {
	return ed.rolePrivileges
}
func (ed *enterpriseData) ManagedNodes() IEnterpriseLink[IManagedNode, int64, int64] {
	return ed.managedNodes
}
func (ed *enterpriseData) UserAliases() IEnterpriseLink[IUserAlias, int64, string] {
	return ed.userAliases
}
func (ed *enterpriseData) SsoServices() IEnterpriseEntity[ISsoService, int64] {
	return ed.ssoServices
}
func (ed *enterpriseData) Bridges() IEnterpriseEntity[IBridge, int64] {
	return ed.bridges
}
func (ed *enterpriseData) Scims() IEnterpriseEntity[IScim, int64] {
	return ed.scims
}
func (ed *enterpriseData) ManagedCompanies() IEnterpriseEntity[IManagedCompany, int64] {
	return ed.managedCompanies
}
func (ed *enterpriseData) RecordTypes() IEnterpriseEntity[vault.IRecordType, string] {
	return ed.recordTypes
}

func newEnterpriseData(ei *enterpriseInfo) *enterpriseData {
	var ed = &enterpriseData{
		enterpriseInfo:   ei,
		licenses:         newLicenseEntity(),
		nodes:            newNodeEntity(),
		roles:            newRoleEntity(),
		users:            newUserEntity(),
		teams:            newTeamEntity(),
		teamUsers:        newTeamUserLink(),
		queuedTeams:      newQueuedTeamEntity(),
		queuedTeamUsers:  newQueuedTeamUserLink(),
		roleUsers:        newRoleUserLink(),
		roleTeams:        newRoleTeamLink(),
		rolePrivileges:   newRolePrivileges(),
		managedNodes:     newManagedNodeLink(),
		roleEnforcements: newRoleEnforcementLink(),
		userAliases:      newUserAliasLink(),
		ssoServices:      newSsoServiceEntity(),
		bridges:          newBridgeEntity(),
		scims:            newScimEntity(),
		emailProvisions:  newEmailProvisionEntity(),
		managedCompanies: newManagedCompanyEntity(),
	}

	ed.teams.registerCascadeDelete(ed.teamUsers.deleteBySubject)
	ed.teams.registerCascadeDelete(ed.queuedTeamUsers.deleteBySubject)
	ed.teams.registerCascadeDelete(ed.roleTeams.deleteByObject)

	ed.users.registerCascadeDelete(ed.teamUsers.deleteByObject)
	ed.users.registerCascadeDelete(ed.roleUsers.deleteByObject)
	ed.users.registerCascadeDelete(ed.queuedTeamUsers.deleteByObject)
	ed.users.registerCascadeDelete(ed.userAliases.deleteBySubject)

	ed.roles.registerCascadeDelete(ed.roleUsers.deleteBySubject)
	ed.roles.registerCascadeDelete(ed.roleTeams.deleteBySubject)
	ed.roles.registerCascadeDelete(ed.roleEnforcements.deleteBySubject)
	ed.roles.registerCascadeDelete(ed.rolePrivileges.deleteBySubject)
	ed.roles.registerCascadeDelete(ed.managedNodes.deleteBySubject)

	ed.queuedTeams.registerCascadeDelete(ed.queuedTeamUsers.deleteBySubject)

	return ed
}
