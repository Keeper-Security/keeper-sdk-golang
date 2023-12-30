package enterprise

func NewNode(nodeId int64) INodeEdit {
	return &node{
		nodeId: nodeId,
	}
}

func CloneNode(n INode) INodeEdit {
	return &node{
		nodeId:               n.NodeId(),
		name:                 n.Name(),
		parentId:             n.ParentId(),
		bridgeId:             n.BridgeId(),
		scimId:               n.ScimId(),
		licenseId:            n.LicenseId(),
		duoEnabled:           n.DuoEnabled(),
		rsaEnabled:           n.RsaEnabled(),
		restrictVisibility:   n.RestrictVisibility(),
		ssoServiceProviderId: n.SsoServiceProviderId(),
		encryptedData:        n.EncryptedData(),
	}
}

func NewRole(roleId int64) IRoleEdit {
	return &role{
		roleId: roleId,
	}
}
func CloneRole(r IRole) IRoleEdit {
	return &role{
		roleId:         r.RoleId(),
		name:           r.Name(),
		nodeId:         r.NodeId(),
		keyType:        r.KeyType(),
		visibleBelow:   r.VisibleBelow(),
		newUserInherit: r.NewUserInherit(),
		roleType:       r.RoleType(),
		encryptedData:  r.EncryptedData(),
	}
}

func NewTeam(teamUid string) ITeamEdit {
	return &team{
		teamUid: teamUid,
	}
}
func CloneTeam(t ITeam) ITeamEdit {
	return &team{
		teamUid:          t.TeamUid(),
		name:             t.Name(),
		nodeId:           t.NodeId(),
		restrictEdit:     t.RestrictEdit(),
		restrictShare:    t.RestrictShare(),
		restrictView:     t.RestrictView(),
		encryptedTeamKey: t.EncryptedTeamKey(),
	}
}

func NewUser(enterpriseUserId int64, username string, status UserStatus) IUserEdit {
	return &user{
		enterpriseUserId: enterpriseUserId,
		username:         username,
		status:           status,
		lock:             0,
	}
}

func NewTeamUser(teamUid string, enterpriseUserId int64) ITeamUserEdit {
	return &teamUser{
		teamUid:          teamUid,
		enterpriseUserId: enterpriseUserId,
		userType:         "USER",
	}
}

func NewRoleUser(roleId int64, enterpriseUserId int64) IRoleUser {
	return &roleUser{
		roleId:           roleId,
		enterpriseUserId: enterpriseUserId,
	}
}

func NewRoleTeam(roleId int64, teamUid string) IRoleTeam {
	return &roleTeam{
		roleId:  roleId,
		teamUid: teamUid,
	}
}

func NewManagedNode(roleId int64, nodeId int64) IManageNodeEdit {
	return &managedNode{
		roleId:        roleId,
		managedNodeId: nodeId,
	}
}
func NewRolePrivilege(roleId int64, nodeId int64) IRolePrivilegeEdit {
	return &rolePrivilege{
		roleId:        roleId,
		managedNodeId: nodeId,
	}
}

func NewRoleEnforcement(roleId int64, enforcementType string) IRoleEnforcementEdit {
	return &roleEnforcement{
		roleId:          roleId,
		enforcementType: enforcementType,
	}
}

func CloneRoleEnforcement(other IRoleEnforcement) IRoleEnforcementEdit {
	return &roleEnforcement{
		roleId:          other.RoleId(),
		enforcementType: other.EnforcementType(),
		value:           other.Value(),
	}
}
