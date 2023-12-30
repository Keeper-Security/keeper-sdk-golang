package enterprise

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/auth"
	"github.com/keeper-security/keeper-sdk-golang/internal/database"
	"github.com/keeper-security/keeper-sdk-golang/internal/json_commands"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_enterprise"
	"strings"
)

func parseEncryptedData(encryptedData string, treeKey []byte) (result *database.EncryptedData, err error) {
	if len(encryptedData) > 0 {
		var data = api.Base64UrlDecode(encryptedData)
		if data, err = api.DecryptAesV1(data, treeKey); err == nil {
			err = json.Unmarshal(data, &result)
		}
	} else {
		err = api.NewKeeperError("Encrypted data is empty")
	}
	return
}

func createEncryptedData(encData *database.EncryptedData, oldData string, treeKey []byte) (result string, err error) {
	var data []byte
	if data, err = json.Marshal(encData); err != nil {
		return
	}
	if len(oldData) > 0 {
		var ed = make(map[string]any)
		var eData = api.Base64UrlDecode(oldData)
		if eData, err = api.DecryptAesV1(eData, treeKey); err == nil {
			if err = json.Unmarshal(eData, &ed); err == nil {
				if eData, err = json.Marshal(ed); err == nil {
					data = eData
				}
			}
		}
	}
	if data, err = api.EncryptAesV1(data, treeKey); err != nil {
		return
	}
	result = api.Base64UrlEncode(data)
	return
}

func prepareTeamRequests(loader IEnterpriseLoader, teamsToAdd []ITeam, teamsToUpdate []ITeam, teamsToDelete []string) (requests []api.IKeeperCommand, errs []error) {
	var eData = loader.EnterpriseData()

	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var teams = loader.EnterpriseData().Teams()
	var dataKey = loader.KeeperAuth().AuthContext().DataKey()

	var err error
	var data []byte
	for _, x := range teamsToAdd {
		var teamUid = x.TeamUid()
		if len(teamUid) == 0 {
			errs = append(errs, fmt.Errorf("team \"%s\" does not have TeamUID assigned", x.Name()))
			continue
		}
		var t = json_commands.EnterpriseTeam{
			TeamUid:       teamUid,
			TeamName:      x.Name(),
			RestrictShare: x.RestrictShare(),
			RestrictEdit:  x.RestrictEdit(),
			RestrictView:  x.RestrictView(),
		}
		t.NodeId = new(int64)
		if x.NodeId() > 0 {
			*t.NodeId = x.NodeId()
		} else {
			*t.NodeId = eData.RootNode().NodeId()
		}
		var r = &json_commands.EnterpriseTeamAddCommand{
			EnterpriseTeam: t,
		}

		var teamKey = api.GenerateAesKey()
		var privKey *rsa.PrivateKey
		var pubKey *rsa.PublicKey
		if privKey, pubKey, err = api.GenerateRsaKey(); err != nil {
			errs = append(errs, err)
			continue
		}
		r.PublicKey = api.Base64UrlEncode(api.UnloadRsaPublicKey(pubKey))

		data = api.UnloadRsaPrivateKey(privKey)
		if data, err = api.EncryptAesV1(data, teamKey); err != nil {
			errs = append(errs, err)
			continue
		}
		r.PrivateKey = api.Base64UrlEncode(data)

		if data, err = api.EncryptAesV2(teamKey, treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		r.EncryptedTeamKey = api.Base64UrlEncode(data)

		if data, err = api.EncryptAesV1(teamKey, dataKey); err != nil {
			errs = append(errs, err)
			continue
		}
		r.TeamKey = api.Base64UrlEncode(data)

		requests = append(requests, r)
	}
	for _, x := range teamsToUpdate {
		var existingTeam = teams.GetEntity(x.TeamUid())
		if existingTeam == nil {
			err = fmt.Errorf("update team: UID \"%s\" not found", x.TeamUid())
			errs = append(errs, err)
			continue
		}
		var t = json_commands.EnterpriseTeam{
			TeamUid:       x.TeamUid(),
			TeamName:      x.Name(),
			RestrictShare: x.RestrictShare(),
			RestrictEdit:  x.RestrictEdit(),
			RestrictView:  x.RestrictView(),
		}
		t.NodeId = new(int64)
		*t.NodeId = x.NodeId()
		var r = &json_commands.EnterpriseTeamUpdateCommand{
			EnterpriseTeam: t,
		}
		requests = append(requests, r)
	}

	for _, teamUid := range teamsToDelete {
		var existingTeam = teams.GetEntity(teamUid)
		if existingTeam == nil {
			errs = append(errs, fmt.Errorf("delete team: UID \"%s\" not found", teamUid))
			continue
		}
		var r = &json_commands.EnterpriseTeamDeleteCommand{
			TeamUid: teamUid,
		}
		requests = append(requests, r)
	}
	return
}

func prepareNodeRequests(loader IEnterpriseLoader, nodesToAdd []INode, nodesToUpdate []INode, nodesToDelete []int64) (requests []api.IKeeperCommand, errs []error) {
	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var nodes = loader.EnterpriseData().Nodes()

	var err error

	for _, x := range nodesToAdd {
		if x.NodeId() == 0 {
			errs = append(errs, fmt.Errorf("Node \"%s\" does not have NodeID", x.Name()))
			continue
		}
		var nodeData = &database.EncryptedData{
			DisplayName: x.Name(),
		}
		var encryptedData string
		if encryptedData, err = createEncryptedData(nodeData, "", treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		var nac = &json_commands.EnterpriseNodeAddCommand{
			EnterpriseNode: json_commands.EnterpriseNode{
				NodeId:        x.NodeId(),
				ParentId:      x.ParentId(),
				EncryptedData: encryptedData,
			},
		}
		if x.RestrictVisibility() {
			nac.RestrictVisibility = new(string)
			*nac.RestrictVisibility = "1"
		}
		requests = append(requests, nac)
	}
	for _, x := range nodesToUpdate {
		var existingNode = nodes.GetEntity(x.NodeId())
		if existingNode == nil {
			errs = append(errs, fmt.Errorf("node UID \"%d\" does not exist", x.NodeId()))
			continue
		}

		var nodeData = &database.EncryptedData{
			DisplayName: x.Name(),
		}
		var encryptedData string
		if encryptedData, err = createEncryptedData(nodeData, existingNode.EncryptedData(), treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		var nuc = &json_commands.EnterpriseNodeUpdateCommand{
			EnterpriseNode: json_commands.EnterpriseNode{
				NodeId:        x.NodeId(),
				ParentId:      x.ParentId(),
				EncryptedData: encryptedData,
			},
		}
		requests = append(requests, nuc)
	}

	for _, nodeId := range nodesToDelete {
		var existingNode = nodes.GetEntity(nodeId)
		if existingNode == nil {
			errs = append(errs, fmt.Errorf("team UID \"%d\" does not exist", nodeId))
			continue
		}

		var r = &json_commands.EnterpriseNodeDeleteCommand{
			NodeId: nodeId,
		}
		requests = append(requests, r)
	}
	return
}

func prepareRoleRequests(loader IEnterpriseLoader, rolesToAdd []IRole, rolesToUpdate []IRole, rolesToDelete []int64) (requests []api.IKeeperCommand, errs []error) {
	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var roles = loader.EnterpriseData().Roles()

	var err error

	for _, x := range rolesToAdd {
		if x.RoleId() == 0 {
			errs = append(errs, fmt.Errorf("Role \"%s\" does not have ID assigned", x.Name()))
			continue
		}
		var roleData = &database.EncryptedData{
			DisplayName: x.Name(),
		}
		var encryptedData string
		if encryptedData, err = createEncryptedData(roleData, "", treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		var rac = &json_commands.EnterpriseRoleAddCommand{
			EnterpriseRole: json_commands.EnterpriseRole{
				RoleId:         x.RoleId(),
				NodeId:         x.NodeId(),
				EncryptedData:  encryptedData,
				VisibleBelow:   new(bool),
				NewUserInherit: new(bool),
			},
		}
		if rac.NodeId == 0 {
			rac.NodeId = loader.EnterpriseData().RootNode().NodeId()
		}
		*rac.VisibleBelow = x.VisibleBelow()
		*rac.NewUserInherit = x.NewUserInherit()
		requests = append(requests, rac)
	}
	for _, x := range rolesToUpdate {
		var existingRole = roles.GetEntity(x.RoleId())
		if existingRole == nil {
			errs = append(errs, fmt.Errorf("role UID \"%d\" does not exist", x.RoleId()))
			continue
		}

		var roleData = &database.EncryptedData{
			DisplayName: x.Name(),
		}
		var encryptedData string
		if encryptedData, err = createEncryptedData(roleData, existingRole.EncryptedData(), treeKey); err != nil {
			errs = append(errs, err)
			continue
		}
		var ruc = &json_commands.EnterpriseRoleUpdateCommand{
			EnterpriseRole: json_commands.EnterpriseRole{
				RoleId:        x.RoleId(),
				NodeId:        x.NodeId(),
				EncryptedData: encryptedData,
			},
		}
		if x.VisibleBelow() != existingRole.VisibleBelow() {
			ruc.VisibleBelow = new(bool)
			*ruc.VisibleBelow = x.VisibleBelow()
		}
		if x.NewUserInherit() != existingRole.NewUserInherit() {
			ruc.NewUserInherit = new(bool)
			*ruc.NewUserInherit = x.NewUserInherit()
		}
		requests = append(requests, ruc)
	}

	for _, roleId := range rolesToDelete {
		var existingRole = roles.GetEntity(roleId)
		if existingRole == nil {
			errs = append(errs, fmt.Errorf("role UID \"%d\" does not exist", roleId))
			continue
		}

		var r = &json_commands.EnterpriseRoleDeleteCommand{
			RoleId: roleId,
		}
		requests = append(requests, r)
	}
	return
}

func prepareTeamUserRequests(loader IEnterpriseLoader, teamUsersToAdd []ITeamUser, teamUsersToRemove []ITeamUser) (requests []api.IKeeperCommand, errs []error) {
	// TODO use teams_enterprise_users_add API
	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var teamUsers = loader.EnterpriseData().TeamUsers()
	var users = loader.EnterpriseData().Users()
	var teams = loader.EnterpriseData().Teams()
	var userKeys = make(map[string]*auth.PublicKeys)
	var teamKeys = make(map[string][]byte)
	var toAdd []ITeamUser
	var toUpdate []ITeamUser

	var err error
	var tu ITeamUser
	for _, tu = range teamUsersToAdd {
		var t = teams.GetEntity(tu.TeamUid())
		if t == nil {
			err = fmt.Errorf("team-user: team UID \"%s\" not found", tu.TeamUid())
			errs = append(errs, err)
			continue
		}
		var u = users.GetEntity(tu.EnterpriseUserId())
		if u == nil {
			errs = append(errs, fmt.Errorf("team-user: user ID \"%d\" not found", tu.EnterpriseUserId()))
			continue
		}
		if u.Status() != "active" {
			errs = append(errs, fmt.Errorf("team-user: user \"%s\" is not active", u.Username()))
			continue
		}
		var otu = teamUsers.GetLink(tu.TeamUid(), tu.EnterpriseUserId())
		if otu == nil {
			toAdd = append(toAdd, tu)
			userKeys[u.Username()] = nil
			teamKeys[tu.TeamUid()] = nil
		} else {
			toUpdate = append(toUpdate, tu)
		}
	}
	if len(userKeys) > 0 {
		errs = append(errs, auth.GetUserPublicKeys(loader.KeeperAuth(), userKeys)...)
	}
	if len(teamKeys) > 0 {
		var uids []string
		for k := range teamKeys {
			uids = append(uids, k)
		}
		var hasMissingKeys = false
		for _, uid := range uids {
			var t = teams.GetEntity(uid)
			if t != nil {
				if len(t.EncryptedTeamKey()) > 0 {
					var data []byte
					if data, err = api.DecryptAesV2(t.EncryptedTeamKey(), treeKey); err == nil {
						teamKeys[uid] = data
					} else {
						hasMissingKeys = true
					}
				} else {
					hasMissingKeys = true
				}
			}
		}
		if hasMissingKeys {
			errs = append(errs, auth.GetTeamKeys(loader.KeeperAuth(), teamKeys)...)
		}
	}

	for _, tu = range toAdd {
		var u = users.GetEntity(tu.EnterpriseUserId())
		if u != nil {
			var userKey = userKeys[u.Username()]
			var teamKey = teamKeys[tu.TeamUid()]
			if userKey != nil && teamKey != nil {
				var rq = &json_commands.EnterpriseTeamUserAddCommand{
					EnterpriseTeamUser: json_commands.EnterpriseTeamUser{
						TeamUid:          tu.TeamUid(),
						EnterpriseUserId: tu.EnterpriseUserId(),
					},
				}
				if typ, ok := proto_enterprise.TeamUserType_value[strings.ToUpper(tu.UserType())]; ok {
					rq.UserType = typ
				}
				if userKey.RsaPublicKey != nil {
					var data []byte
					if data, err = api.EncryptRsa(teamKey, userKey.RsaPublicKey); err == nil {
						rq.TeamKey = api.Base64UrlEncode(data)
					} else {
						errs = append(errs, err)
					}
				}
				requests = append(requests, rq)
			}
		}
	}

	for _, tu = range toUpdate {
		var rq = &json_commands.EnterpriseTeamUserUpdateCommand{
			EnterpriseTeamUser: json_commands.EnterpriseTeamUser{
				TeamUid:          tu.TeamUid(),
				EnterpriseUserId: tu.EnterpriseUserId(),
			},
		}
		if typ, ok := proto_enterprise.TeamUserType_value[strings.ToUpper(tu.UserType())]; ok {
			rq.UserType = typ
		}
		requests = append(requests, rq)
	}

	for _, tu = range teamUsersToRemove {
		var ctu = teamUsers.GetLink(tu.TeamUid(), tu.EnterpriseUserId())
		if ctu == nil {
			errs = append(errs, fmt.Errorf("team=\"%s\" does not contain user=%d", tu.TeamUid(), tu.EnterpriseUserId()))
			continue
		}
		var rq = &json_commands.EnterpriseTeamUserRemoveCommand{
			EnterpriseTeamUser: json_commands.EnterpriseTeamUser{
				TeamUid:          tu.TeamUid(),
				EnterpriseUserId: tu.EnterpriseUserId(),
			},
		}
		requests = append(requests, rq)
	}

	return
}

func prepareRoleUserRequests(loader IEnterpriseLoader, roleUsersToAdd []IRoleUser, roleUsersToRemove []IRoleUser) (requests []api.IKeeperCommand, errs []error) {
	var roleUsers = loader.EnterpriseData().RoleUsers()
	var managedNodes = loader.EnterpriseData().ManagedNodes()
	var users = loader.EnterpriseData().Users()
	var roles = loader.EnterpriseData().Roles()

	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var userKeys = make(map[string]*auth.PublicKeys)
	var roleKeys = make(map[int64][]byte)
	var toAdd []IRoleUser

	var err error
	var ru IRoleUser
	for _, ru = range roleUsersToAdd {
		var r = roles.GetEntity(ru.RoleId())
		if r == nil {
			errs = append(errs, fmt.Errorf("role-user: role ID \"%d\" not found", ru.RoleId()))
			continue
		}
		var isAdminRole = false
		managedNodes.GetLinksBySubject(ru.RoleId(), func(x IManagedNode) bool {
			isAdminRole = true
			return false
		})

		var u = users.GetEntity(ru.EnterpriseUserId())
		if u == nil {
			errs = append(errs, fmt.Errorf("role-user: user ID \"%d\" not found", ru.EnterpriseUserId()))
			continue
		}
		if u.Status() != "active" && isAdminRole {
			errs = append(errs, fmt.Errorf("role-user: inactive user \"%s\" cannot be added to admin role.", u.Username()))
			continue
		}
		var otu = roleUsers.GetLink(ru.RoleId(), ru.EnterpriseUserId())
		if otu != nil {
			toAdd = append(toAdd, ru)
			if isAdminRole {
				roleKeys[ru.RoleId()] = nil
				userKeys[u.Username()] = nil
			}
		}
	}

	if len(userKeys) > 0 {
		errs = append(errs, auth.GetUserPublicKeys(loader.KeeperAuth(), userKeys)...)
	}
	if len(roleKeys) > 0 {
		if err = loader.LoadRoleKeys(roleKeys); err != nil {
			errs = append(errs, err)
		}
	}

	for _, ru = range toAdd {
		var rq = &json_commands.EnterpriseRoleUserAddCommand{
			EnterpriseRoleUser: json_commands.EnterpriseRoleUser{
				RoleId:           ru.RoleId(),
				EnterpriseUserId: ru.EnterpriseUserId(),
			},
		}
		var isAdminRole = false
		managedNodes.GetLinksBySubject(ru.RoleId(), func(x IManagedNode) bool {
			isAdminRole = true
			return false
		})
		if isAdminRole {
			var userKey *auth.PublicKeys
			var roleKey []byte
			var u = users.GetEntity(ru.EnterpriseUserId())
			if u != nil {
				userKey = userKeys[u.Username()]
			}
			roleKey = roleKeys[ru.RoleId()]
			if userKey != nil && userKey.RsaPublicKey != nil && roleKey != nil {
				if userKey.RsaPublicKey != nil {
					var data []byte
					if data, err = api.EncryptRsa(roleKey, userKey.RsaPublicKey); err == nil {
						rq.RoleAdminKey = api.Base64UrlEncode(data)
						if data, err = api.EncryptRsa(treeKey, userKey.RsaPublicKey); err == nil {
							rq.TreeKey = api.Base64UrlEncode(data)
						}
					}
				}
			}
		}
		if err == nil {
			requests = append(requests, rq)
		} else {
			errs = append(errs, err)
		}
	}

	for _, ru = range roleUsersToRemove {
		var cru = roleUsers.GetLink(ru.RoleId(), ru.EnterpriseUserId())
		if cru == nil {
			errs = append(errs, fmt.Errorf("roleId=\"%d\" does not contain userId=\"%d\"", ru.RoleId(), ru.EnterpriseUserId()))
			continue
		}
		var rq = &json_commands.EnterpriseRoleUserRemoveCommand{
			EnterpriseRoleUser: json_commands.EnterpriseRoleUser{
				RoleId:           ru.RoleId(),
				EnterpriseUserId: ru.EnterpriseUserId(),
			},
		}
		requests = append(requests, rq)
	}

	return
}

func prepareRolePrivilegesRequests(loader IEnterpriseLoader, privileges []IRolePrivilege) (requests []api.IKeeperCommand, errs []error) {
	var err error
	var rps = loader.EnterpriseData().RolePrivileges()
	var rus = loader.EnterpriseData().RoleUsers()
	var uss = loader.EnterpriseData().Users()
	var roleKeys = make(map[int64][]byte)
	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	var addPrivileges []*json_commands.ManagedNodePrivilegeAddCommand
	var removePrivileges []*json_commands.ManagedNodePrivilegeRemoveCommand
	for _, rp := range privileges {
		var toAdd []string
		var toRemove []string
		var rpp = rp.ToSet()
		var orp = rps.GetLink(rp.RoleId(), rp.ManagedNodeId())
		if orp != nil {
			var orpp = orp.ToSet()
			var s = api.NewSet[string]()
			s.Union(orpp.ToArray())
			s.Difference(rpp.ToArray())
			toAdd = s.ToArray()
			s = api.NewSet[string]()
			s.Union(rpp.ToArray())
			s.Difference(orpp.ToArray())
			toRemove = s.ToArray()
		} else {
			toAdd = rpp.ToArray()
		}
		if len(toAdd) > 0 {
			for _, p := range toAdd {
				addPrivileges = append(addPrivileges, &json_commands.ManagedNodePrivilegeAddCommand{
					ManagedNodePrivilege: json_commands.ManagedNodePrivilege{
						ManagedNode: json_commands.ManagedNode{
							RoleId:        rp.RoleId(),
							ManagedNodeId: rp.ManagedNodeId(),
						},
						Privilege: p,
					},
				})
				if p == "transfer_account" {
					roleKeys[rp.RoleId()] = nil
				}
			}
		}
		if len(toRemove) > 0 {
			for _, p := range toRemove {
				removePrivileges = append(removePrivileges, &json_commands.ManagedNodePrivilegeRemoveCommand{
					ManagedNodePrivilege: json_commands.ManagedNodePrivilege{
						ManagedNode: json_commands.ManagedNode{
							RoleId:        rp.RoleId(),
							ManagedNodeId: rp.ManagedNodeId(),
						},
						Privilege: p,
					},
				})
			}
		}
	}

	if len(roleKeys) > 0 {
		if err = loader.LoadRoleKeys(roleKeys); err != nil {
			errs = append(errs, err)
		}
	}
	var userId int64
	var userIds = make(map[int64]string)
	for userId = range roleKeys {
		rus.GetLinksBySubject(userId, func(ru IRoleUser) bool {
			userIds[userId] = ""
			return true
		})
	}
	var userKeys = make(map[string]*auth.PublicKeys)
	if len(userIds) > 0 {
		for userId = range userIds {
			var u = uss.GetEntity(userId)
			if u != nil {
				userKeys[u.Username()] = nil
				userIds[userId] = u.Username()
			}
		}
		errs = append(errs, auth.GetUserPublicKeys(loader.KeeperAuth(), userKeys)...)
	}
	for _, e := range addPrivileges {
		if e.Privilege == "transfer_account" {
			var data []byte
			if roleKey, ok := roleKeys[e.RoleId]; ok {
				if roleKey == nil {
					roleKey = api.GenerateAesKey()
					roleKeys[e.RoleId] = roleKey
					if data, err = api.EncryptAesV2(roleKey, treeKey); err != nil {
						errs = append(errs, err)
						continue
					}
					var s = new(string)
					*s = api.Base64UrlEncode(data)
					e.RoleKeyEncWithTreeKey = s
				}
				var privateKey *rsa.PrivateKey
				var publicKey *rsa.PublicKey
				if privateKey, publicKey, err = api.GenerateRsaKey(); err == nil {
					var privateKeyData = api.UnloadRsaPublicKey(publicKey)
					var s = new(string)
					*s = api.Base64UrlEncode(privateKeyData)
					e.RolePublicKey = s
					data = api.UnloadRsaPrivateKey(privateKey)
					if data, err = api.EncryptAesV1(data, roleKey); err == nil {
						s = new(string)
						*s = api.Base64UrlEncode(data)
						e.RolePrivateKey = s
					} else {
						errs = append(errs, err)
					}
					rus.GetLinksBySubject(e.RoleId, func(ru IRoleUser) bool {
						var username string
						if username, ok = userIds[ru.EnterpriseUserId()]; ok {
							var keys *auth.PublicKeys
							if keys, ok = userKeys[username]; ok {
								if keys.RsaPublicKey != nil {
									if data, err = api.EncryptRsa(privateKeyData, keys.RsaPublicKey); err == nil {
										e.RoleKeys = append(e.RoleKeys, &json_commands.RoleUserKey{
											EnterpriseUserId: ru.EnterpriseUserId(),
											RoleKey:          api.Base64UrlEncode(data),
										})
									}
								}
							}
						}
						return true
					})
				} else {
					errs = append(errs, err)
				}
			}
		}
	}
	requests = append(requests, api.SliceSelect(addPrivileges, func(x *json_commands.ManagedNodePrivilegeAddCommand) api.IKeeperCommand {
		return x
	})...)

	requests = append(requests, api.SliceSelect(removePrivileges, func(x *json_commands.ManagedNodePrivilegeRemoveCommand) api.IKeeperCommand {
		return x
	})...)

	return
}

func prepareManagedNodesRequests(loader IEnterpriseLoader, managedNodesToAdd []IManagedNode, managedNodesToUpdate []IManagedNode, managedNodesToRemove []IManagedNode) (requests []api.IKeeperCommand, errs []error) {
	var mns = loader.EnterpriseData().ManagedNodes()
	var ns = loader.EnterpriseData().Nodes()
	var rs = loader.EnterpriseData().Roles()
	var rus = loader.EnterpriseData().RoleUsers()
	var us = loader.EnterpriseData().Users()
	var rts = loader.EnterpriseData().RoleTeams()
	var err error
	for _, e := range managedNodesToUpdate {
		var l = mns.GetLink(e.RoleId(), e.ManagedNodeId())
		if l == nil {
			err = fmt.Errorf("update managed node: does not exist. RoleID=\"%d\"; ManagedNodeId: \"%d\"", e.RoleId(), e.ManagedNodeId())
			errs = append(errs, err)
			continue
		}
		if l.CascadeNodeManagement() != e.CascadeNodeManagement() {
			requests = append(requests, &json_commands.RoleManagedNodeUpdateCommand{
				ManagedNode: json_commands.ManagedNode{
					RoleId:        e.RoleId(),
					ManagedNodeId: e.ManagedNodeId(),
				},
				CascadeNodeManagement: e.CascadeNodeManagement(),
			})
		}
	}

	var userIds = api.NewSet[int64]()
	var verified = api.NewSet[LinkKey[int64, int64]]()
	for _, e := range managedNodesToAdd {
		var l = mns.GetLink(e.RoleId(), e.ManagedNodeId())
		if l != nil {
			err = fmt.Errorf("add managed node: already exists. RoleID=\"%d\"; ManagedNodeId: \"%d\"", e.RoleId(), e.ManagedNodeId())
			errs = append(errs, err)
			continue
		}
		var r = rs.GetEntity(e.RoleId())
		if r == nil {
			err = fmt.Errorf("add managed node: role does not exist. RoleID=\"%d\"; ManagedNodeId: \"%d\"", e.RoleId(), e.ManagedNodeId())
			errs = append(errs, err)
			continue
		}
		var n = ns.GetEntity(e.ManagedNodeId())
		if n == nil {
			err = fmt.Errorf("add managed node: node does not exist. RoleID=\"%d\"; ManagedNodeId: \"%d\"", e.RoleId(), e.ManagedNodeId())
			errs = append(errs, err)
			continue
		}
		var ok = true
		rts.GetLinksBySubject(e.RoleId(), func(x IRoleTeam) bool {
			ok = false
			return false
		})
		if !ok {
			err = fmt.Errorf("add managed node: admin role should not contain teams. RoleID=\"%d\"; ManagedNodeId: \"%d\"", e.RoleId(), e.ManagedNodeId())
			errs = append(errs, err)
			continue
		}
		ok = true
		rus.GetLinksBySubject(e.RoleId(), func(x IRoleUser) bool {
			var u = us.GetEntity(x.EnterpriseUserId())
			if u.Status() == UserStatus_Inactive {
				ok = false
			}
			return ok
		})
		if !ok {
			err = fmt.Errorf("add managed node: admin role should not contain invited users. RoleID=\"%d\"; ManagedNodeId: \"%d\"", e.RoleId(), e.ManagedNodeId())
			errs = append(errs, err)
			continue
		}
		rus.GetLinksBySubject(e.RoleId(), func(x IRoleUser) bool {
			userIds.Add(x.EnterpriseUserId())
			return true
		})
		verified.Add(LinkKey[int64, int64]{
			V1: e.RoleId(),
			V2: e.ManagedNodeId(),
		})
	}

	var userKeys = make(map[string]*auth.PublicKeys)
	if len(userIds) > 0 {
		for x := range userIds {
			var u = us.GetEntity(x)
			if u != nil {
				userKeys[u.Username()] = nil
			}
		}
		if len(userKeys) > 0 {
			errs = append(errs, auth.GetUserPublicKeys(loader.KeeperAuth(), userKeys)...)
		}
	}

	var ok bool
	var treeKey = loader.EnterpriseData().EnterpriseInfo().TreeKey()
	for _, e := range managedNodesToAdd {
		var l = LinkKey[int64, int64]{
			V1: e.RoleId(),
			V2: e.ManagedNodeId(),
		}
		if verified.Has(l) {
			var rq = &json_commands.RoleManagedNodeAddCommand{
				ManagedNode: json_commands.ManagedNode{
					RoleId:        e.RoleId(),
					ManagedNodeId: e.ManagedNodeId(),
				},
				CascadeNodeManagement: e.CascadeNodeManagement(),
			}
			rus.GetLinksBySubject(e.RoleId(), func(x IRoleUser) bool {
				var u = us.GetEntity(x.EnterpriseUserId())
				if u != nil {
					var pk *auth.PublicKeys
					if pk, ok = userKeys[u.Username()]; ok {
						if pk.RsaPublicKey != nil {
							var data []byte
							if data, err = api.EncryptRsa(treeKey, pk.RsaPublicKey); err != nil {
								rq.TreeKeys = append(rq.TreeKeys, &json_commands.RoleUserKey{
									EnterpriseUserId: u.EnterpriseUserId(),
									RoleKey:          api.Base64UrlEncode(data),
								})
							}
						}
					}
				}
				return true
			})
			requests = append(requests, rq)
		}
	}

	for _, e := range managedNodesToRemove {
		var l = mns.GetLink(e.RoleId(), e.ManagedNodeId())
		if l == nil {
			err = fmt.Errorf("remove managed node: does not exists. RoleID=\"%d\"; ManagedNodeId: \"%d\"", e.RoleId(), e.ManagedNodeId())
			errs = append(errs, err)
			continue
		}
		requests = append(requests, &json_commands.RoleManagedNodeRemoveCommand{
			ManagedNode: json_commands.ManagedNode{
				RoleId:        e.RoleId(),
				ManagedNodeId: e.ManagedNodeId(),
			},
		})
	}
	return
}

func prepareRoleEnforcementsRequests(loader IEnterpriseLoader, enforcementsToSet []IRoleEnforcement) (requests []api.IKeeperCommand, errs []error) {
	var res = loader.EnterpriseData().RoleEnforcements()
	var rs = loader.EnterpriseData().Roles()
	var err error
	for _, e := range enforcementsToSet {
		var ok bool
		var r = rs.GetEntity(e.RoleId())
		if r == nil {
			errs = append(errs, fmt.Errorf("role enforcement is not set: RoleID=\"%d\"", e.RoleId()))
			continue
		}
		var cmpValue = e.Value()
		var shouldRemove = false
		var ef = res.GetLink(e.RoleId(), e.EnforcementType())
		if len(e.Value()) == 0 {
			if ef != nil {
				shouldRemove = true
			} else {
				continue
			}
		} else {
			var eType string
			if eType, ok = allEnforcements[e.EnforcementType()]; ok {
				if cmpValue, shouldRemove, err = ToEnforcementValue(loader, eType, e.Value()); err != nil {
					errs = append(errs, err)
					continue
				}
			}
		}
		if shouldRemove {
			requests = append(requests, &json_commands.RoleEnforcementRemoveCommand{
				RoleEnforcement: json_commands.RoleEnforcement{
					RoleId:      e.RoleId(),
					Enforcement: e.EnforcementType(),
				},
			})
		} else {
			var value interface{}
			if len(cmpValue) > 0 {
				value = cmpValue
			}
			if ef == nil {
				requests = append(requests, &json_commands.RoleEnforcementAddCommand{
					RoleEnforcement: json_commands.RoleEnforcement{
						RoleId:      e.RoleId(),
						Enforcement: e.EnforcementType(),
					},
					Value: value,
				})
			} else {
				if cmpValue != ef.Value() {
					requests = append(requests, &json_commands.RoleEnforcementUpdateCommand{
						RoleEnforcement: json_commands.RoleEnforcement{
							RoleId:      e.RoleId(),
							Enforcement: e.EnforcementType(),
						},
						Value: value,
					})
				}
			}
		}
	}
	return
}
