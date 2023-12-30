package enterprise

import (
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/storage"
	"github.com/keeper-security/keeper-sdk-golang/vault"
	"sort"
)

type proxyEnterpriseEntity[T storage.IUid[K], K storage.Key] struct {
	origEntities    IEnterpriseEntity[T, K]
	newEntities     map[K]T
	removedEntities api.Set[K]
}

func (cee *proxyEnterpriseEntity[T, K]) GetAllEntities(cb func(T) bool) {
	if cee.newEntities != nil {
		for _, v := range cee.newEntities {
			if !cb(v) {
				return
			}
		}
	}
	cee.origEntities.GetAllEntities(func(t T) bool {
		var uid = t.Uid()
		if cee.removedEntities != nil {
			if cee.removedEntities.Has(uid) {
				return true
			}
		}
		var ok bool
		if cee.newEntities != nil {
			if _, ok = cee.newEntities[uid]; ok {
				return true
			}
		}
		return cb(t)
	})
}
func (cee *proxyEnterpriseEntity[T, K]) GetEntity(uid K) (t T) {
	if cee.removedEntities != nil {
		if cee.removedEntities.Has(uid) {
			return
		}
	}

	var ok bool
	if cee.newEntities != nil {
		if t, ok = cee.newEntities[uid]; ok {
			return
		}
	}
	t = cee.origEntities.GetEntity(uid)
	return
}

var _ IEnterpriseLink[ITeamUser, string, int64] = new(proxyEnterpriseLink[ITeamUser, string, int64])

type proxyEnterpriseLink[T storage.IUidLink[KS, KO], KS storage.Key, KO storage.Key] struct {
	origLinks    IEnterpriseLink[T, KS, KO]
	newLinks     map[LinkKey[KS, KO]]T
	removedLinks api.Set[LinkKey[KS, KO]]
}

func (cel *proxyEnterpriseLink[T, KS, KO]) GetLink(subjectUid KS, objectUid KO) (t T) {
	var key = LinkKey[KS, KO]{
		V1: subjectUid,
		V2: objectUid,
	}
	if cel.removedLinks != nil {
		if cel.removedLinks.Has(key) {
			return
		}
	}
	var ok bool
	if cel.newLinks != nil {
		if t, ok = cel.newLinks[key]; ok {
			return
		}
	}
	t = cel.origLinks.GetLink(subjectUid, objectUid)
	return
}
func (cel *proxyEnterpriseLink[T, KS, KO]) GetAllLinks(cb func(T) bool) {
	if cel.newLinks != nil {
		for _, v := range cel.newLinks {
			if !cb(v) {
				return
			}
		}
	}
	cel.origLinks.GetAllLinks(func(t T) bool {
		var key = LinkKey[KS, KO]{
			V1: t.SubjectUid(),
			V2: t.ObjectUid(),
		}
		if cel.removedLinks != nil {
			if cel.removedLinks.Has(key) {
				return true
			}
		}
		var ok bool
		if cel.newLinks != nil {
			if _, ok = cel.newLinks[key]; ok {
				return true
			}
		}
		return cb(t)
	})
}

func (cel *proxyEnterpriseLink[T, KS, KO]) GetLinksBySubject(subjectUid KS, cb func(T) bool) {
	if cel.newLinks != nil {
		for _, v := range cel.newLinks {
			if v.SubjectUid() == subjectUid {
				if !cb(v) {
					return
				}
			}
		}
	}
	cel.origLinks.GetLinksBySubject(subjectUid, func(t T) bool {
		var key = LinkKey[KS, KO]{
			V1: t.SubjectUid(),
			V2: t.ObjectUid(),
		}
		if cel.removedLinks != nil {
			if cel.removedLinks.Has(key) {
				return true
			}
		}
		var ok bool
		if cel.newLinks != nil {
			if _, ok = cel.newLinks[key]; ok {
				return true
			}
		}
		return cb(t)
	})
}

func (cel *proxyEnterpriseLink[T, KS, KO]) GetLinksByObject(objectUid KO, cb func(T) bool) {
	if cel.newLinks != nil {
		for _, v := range cel.newLinks {
			if v.ObjectUid() == objectUid {
				if !cb(v) {
					return
				}
			}
		}
	}
	cel.origLinks.GetLinksByObject(objectUid, func(t T) bool {
		var key = LinkKey[KS, KO]{
			V1: t.SubjectUid(),
			V2: t.ObjectUid(),
		}
		if cel.removedLinks != nil {
			if cel.removedLinks.Has(key) {
				return true
			}
		}
		var ok bool
		if cel.newLinks != nil {
			if _, ok = cel.newLinks[key]; ok {
				return true
			}
		}
		return cb(t)
	})
}

var _ IEnterpriseManagement = new(proxyEnterpriseManagement)

type proxyEnterpriseManagement struct {
	enterpriseManagement IEnterpriseManagement
	nodes                *proxyEnterpriseEntity[INode, int64]
	roles                *proxyEnterpriseEntity[IRole, int64]
	roleUsers            *proxyEnterpriseLink[IRoleUser, int64, int64]
	roleTeams            *proxyEnterpriseLink[IRoleTeam, int64, string]
	teams                *proxyEnterpriseEntity[ITeam, string]
	teamUsers            *proxyEnterpriseLink[ITeamUser, string, int64]
	managedNodes         *proxyEnterpriseLink[IManagedNode, int64, int64]
	rolePrivileges       *proxyEnterpriseLink[IRolePrivilege, int64, int64]
	roleEnforcements     *proxyEnterpriseLink[IRoleEnforcement, int64, string]
}

func (cem *proxyEnterpriseManagement) GetEnterpriseId() (int64, error) {
	return cem.enterpriseManagement.GetEnterpriseId()
}
func (cem *proxyEnterpriseManagement) EnterpriseData() IEnterpriseData {
	return cem
}
func (cem *proxyEnterpriseManagement) EnterpriseInfo() IEnterpriseInfo {
	return cem.enterpriseManagement.EnterpriseData().EnterpriseInfo()
}
func (cem *proxyEnterpriseManagement) RootNode() INode {
	return cem.enterpriseManagement.EnterpriseData().RootNode()
}

func (cem *proxyEnterpriseManagement) Nodes() IEnterpriseEntity[INode, int64] {
	if cem.nodes == nil {
		cem.nodes = &proxyEnterpriseEntity[INode, int64]{
			origEntities: cem.enterpriseManagement.EnterpriseData().Nodes(),
		}
	}
	return cem.nodes
}
func (cem *proxyEnterpriseManagement) Roles() IEnterpriseEntity[IRole, int64] {
	if cem.roles == nil {
		cem.roles = &proxyEnterpriseEntity[IRole, int64]{
			origEntities: cem.enterpriseManagement.EnterpriseData().Roles(),
		}
	}
	return cem.roles
}
func (cem *proxyEnterpriseManagement) Users() IEnterpriseEntity[IUser, int64] {
	return cem.enterpriseManagement.EnterpriseData().Users()
}
func (cem *proxyEnterpriseManagement) Teams() IEnterpriseEntity[ITeam, string] {
	if cem.teams == nil {
		cem.teams = &proxyEnterpriseEntity[ITeam, string]{
			origEntities: cem.enterpriseManagement.EnterpriseData().Teams(),
		}
	}
	return cem.teams
}
func (cem *proxyEnterpriseManagement) TeamUsers() IEnterpriseLink[ITeamUser, string, int64] {
	if cem.teamUsers == nil {
		cem.teamUsers = &proxyEnterpriseLink[ITeamUser, string, int64]{
			origLinks: cem.enterpriseManagement.EnterpriseData().TeamUsers(),
		}
	}
	return cem.teamUsers
}
func (cem *proxyEnterpriseManagement) QueuedTeams() IEnterpriseEntity[IQueuedTeam, string] {
	return cem.enterpriseManagement.EnterpriseData().QueuedTeams()
}
func (cem *proxyEnterpriseManagement) QueuedTeamUsers() IEnterpriseLink[IQueuedTeamUser, string, int64] {
	return cem.enterpriseManagement.EnterpriseData().QueuedTeamUsers()
}
func (cem *proxyEnterpriseManagement) RoleUsers() IEnterpriseLink[IRoleUser, int64, int64] {
	if cem.roleUsers == nil {
		cem.roleUsers = &proxyEnterpriseLink[IRoleUser, int64, int64]{
			origLinks: cem.enterpriseManagement.EnterpriseData().RoleUsers(),
		}
	}
	return cem.roleUsers
}
func (cem *proxyEnterpriseManagement) RoleTeams() IEnterpriseLink[IRoleTeam, int64, string] {
	if cem.roleTeams == nil {
		cem.roleTeams = &proxyEnterpriseLink[IRoleTeam, int64, string]{
			origLinks: cem.enterpriseManagement.EnterpriseData().RoleTeams(),
		}
	}
	return cem.roleTeams
}
func (cem *proxyEnterpriseManagement) ManagedNodes() IEnterpriseLink[IManagedNode, int64, int64] {
	if cem.managedNodes == nil {
		cem.managedNodes = &proxyEnterpriseLink[IManagedNode, int64, int64]{
			origLinks: cem.enterpriseManagement.EnterpriseData().ManagedNodes(),
		}
	}
	return cem.managedNodes
}
func (cem *proxyEnterpriseManagement) RolePrivileges() IEnterpriseLink[IRolePrivilege, int64, int64] {
	if cem.rolePrivileges == nil {
		cem.rolePrivileges = &proxyEnterpriseLink[IRolePrivilege, int64, int64]{
			origLinks: cem.enterpriseManagement.EnterpriseData().RolePrivileges(),
		}
	}
	return cem.rolePrivileges
}
func (cem *proxyEnterpriseManagement) RoleEnforcements() IEnterpriseLink[IRoleEnforcement, int64, string] {
	if cem.roleEnforcements == nil {
		cem.roleEnforcements = &proxyEnterpriseLink[IRoleEnforcement, int64, string]{
			origLinks: cem.enterpriseManagement.EnterpriseData().RoleEnforcements(),
		}
	}
	return cem.roleEnforcements
}
func (cem *proxyEnterpriseManagement) Licenses() IEnterpriseEntity[ILicense, int64] {
	return cem.enterpriseManagement.EnterpriseData().Licenses()
}
func (cem *proxyEnterpriseManagement) UserAliases() IEnterpriseLink[IUserAlias, int64, string] {
	return cem.enterpriseManagement.EnterpriseData().UserAliases()
}
func (cem *proxyEnterpriseManagement) SsoServices() IEnterpriseEntity[ISsoService, int64] {
	return cem.enterpriseManagement.EnterpriseData().SsoServices()
}
func (cem *proxyEnterpriseManagement) Bridges() IEnterpriseEntity[IBridge, int64] {
	return cem.enterpriseManagement.EnterpriseData().Bridges()
}
func (cem *proxyEnterpriseManagement) Scims() IEnterpriseEntity[IScim, int64] {
	return cem.enterpriseManagement.EnterpriseData().Scims()
}
func (cem *proxyEnterpriseManagement) ManagedCompanies() IEnterpriseEntity[IManagedCompany, int64] {
	return cem.enterpriseManagement.EnterpriseData().ManagedCompanies()
}
func (cem *proxyEnterpriseManagement) RecordTypes() IEnterpriseEntity[vault.IRecordType, string] {
	return cem.enterpriseManagement.EnterpriseData().RecordTypes()
}

func (cem *proxyEnterpriseManagement) ModifyNodes(nodesToAdd []INode, nodesToUpdate []INode, nodesToDelete []int64) []error {
	if nodesToAdd != nil || nodesToUpdate != nil {
		if cem.nodes.newEntities == nil {
			cem.nodes.newEntities = make(map[int64]INode)
		}
		for _, n := range nodesToAdd {
			cem.nodes.newEntities[n.Uid()] = n
		}
		for _, n := range nodesToUpdate {
			cem.nodes.newEntities[n.Uid()] = n
		}
	}
	if nodesToDelete != nil {
		if cem.nodes.removedEntities == nil {
			cem.nodes.removedEntities = api.NewSet[int64]()
		}
		for _, uid := range nodesToDelete {
			if cem.nodes.newEntities != nil {
				delete(cem.nodes.newEntities, uid)
			}
			var origNode = cem.nodes.origEntities.GetEntity(uid)
			if origNode != nil {
				cem.nodes.removedEntities.Add(uid)
			}
		}
	}
	return nil
}
func (cem *proxyEnterpriseManagement) ModifyRoles(rolesToAdd []IRole, rolesToUpdate []IRole, rolesToDelete []int64) []error {
	if rolesToAdd != nil || rolesToUpdate != nil {
		if cem.roles.newEntities == nil {
			cem.roles.newEntities = make(map[int64]IRole)
		}
		for _, n := range rolesToAdd {
			cem.roles.newEntities[n.Uid()] = n
		}
		for _, n := range rolesToUpdate {
			cem.roles.newEntities[n.Uid()] = n
		}
	}
	if rolesToDelete != nil {
		if cem.roles.removedEntities == nil {
			cem.roles.removedEntities = api.NewSet[int64]()
		}
		for _, uid := range rolesToDelete {
			if cem.roles.newEntities != nil {
				delete(cem.roles.newEntities, uid)
			}
			var origRole = cem.roles.origEntities.GetEntity(uid)
			if origRole != nil {
				cem.roles.removedEntities.Add(uid)
			}
		}
	}
	return nil
}
func (cem *proxyEnterpriseManagement) ModifyTeams(teamsToAdd []ITeam, teamsToUpdate []ITeam, teamsToDelete []string) []error {
	if teamsToAdd != nil || teamsToUpdate != nil {
		if cem.teams.newEntities == nil {
			cem.teams.newEntities = make(map[string]ITeam)
		}
		for _, n := range teamsToAdd {
			cem.teams.newEntities[n.Uid()] = n
		}
		for _, n := range teamsToUpdate {
			cem.teams.newEntities[n.Uid()] = n
		}
	}
	if teamsToDelete != nil {
		if cem.teams.removedEntities == nil {
			cem.teams.removedEntities = api.NewSet[string]()
		}
		for _, uid := range teamsToDelete {
			if cem.teams.newEntities != nil {
				delete(cem.teams.newEntities, uid)
			}
			var origTeam = cem.teams.origEntities.GetEntity(uid)
			if origTeam != nil {
				cem.teams.removedEntities.Add(uid)
			}
		}
	}
	return nil
}
func (cem *proxyEnterpriseManagement) ModifyTeamUsers(teamUsersToAdd []ITeamUser, teamUsersToRemove []ITeamUser) []error {
	var link LinkKey[string, int64]
	if teamUsersToAdd != nil {
		if cem.teamUsers.newLinks == nil {
			cem.teamUsers.newLinks = make(map[LinkKey[string, int64]]ITeamUser)
		}
		for _, n := range teamUsersToAdd {
			link.V1 = n.TeamUid()
			link.V2 = n.EnterpriseUserId()
			cem.teamUsers.newLinks[link] = n
		}
	}
	if teamUsersToRemove != nil {
		if cem.teamUsers.removedLinks == nil {
			cem.teamUsers.removedLinks = api.NewSet[LinkKey[string, int64]]()
		}
		for _, n := range teamUsersToRemove {
			link.V1 = n.TeamUid()
			link.V2 = n.EnterpriseUserId()
			if cem.teamUsers.newLinks != nil {
				delete(cem.teamUsers.newLinks, link)
			}
			var origTeamUser = cem.teamUsers.origLinks.GetLink(link.V1, link.V2)
			if origTeamUser != nil {
				cem.teamUsers.removedLinks.Add(link)
			}
		}
	}
	return nil
}
func (cem *proxyEnterpriseManagement) ModifyRoleUsers(roleUsersToAdd []IRoleUser, roleUsersToRemove []IRoleUser) []error {
	var link LinkKey[int64, int64]
	if roleUsersToAdd != nil {
		if cem.roleUsers.newLinks == nil {
			cem.roleUsers.newLinks = make(map[LinkKey[int64, int64]]IRoleUser)
		}
		for _, n := range roleUsersToAdd {
			link.V1 = n.RoleId()
			link.V2 = n.EnterpriseUserId()
			cem.roleUsers.newLinks[link] = n
		}
	}
	if roleUsersToRemove != nil {
		if cem.roleUsers.removedLinks == nil {
			cem.roleUsers.removedLinks = api.NewSet[LinkKey[int64, int64]]()
		}
		for _, n := range roleUsersToRemove {
			link.V1 = n.RoleId()
			link.V2 = n.EnterpriseUserId()
			if cem.roleUsers.newLinks != nil {
				delete(cem.roleUsers.newLinks, link)
			}
			var origRoleUser = cem.roleUsers.origLinks.GetLink(link.V1, link.V2)
			if origRoleUser != nil {
				cem.roleUsers.removedLinks.Add(link)
			}
		}
	}
	return nil
}
func (cem *proxyEnterpriseManagement) ModifyRoleTeams(roleTeamsToAdd []IRoleTeam, roleTeamsToRemove []IRoleTeam) []error {
	var link LinkKey[int64, string]
	if roleTeamsToAdd != nil {
		if cem.roleTeams.newLinks == nil {
			cem.roleTeams.newLinks = make(map[LinkKey[int64, string]]IRoleTeam)
		}
		for _, n := range roleTeamsToAdd {
			link.V1 = n.RoleId()
			link.V2 = n.TeamUid()
			cem.roleTeams.newLinks[link] = n
		}
	}
	if roleTeamsToRemove != nil {
		if cem.roleTeams.removedLinks == nil {
			cem.roleTeams.removedLinks = api.NewSet[LinkKey[int64, string]]()
		}
		for _, n := range roleTeamsToRemove {
			link.V1 = n.RoleId()
			link.V2 = n.TeamUid()
			if cem.roleTeams.newLinks != nil {
				delete(cem.roleTeams.newLinks, link)
			}
			var origRoleTeam = cem.roleTeams.origLinks.GetLink(link.V1, link.V2)
			if origRoleTeam != nil {
				cem.roleTeams.removedLinks.Add(link)
			}
		}
	}
	return nil
}

func (cem *proxyEnterpriseManagement) ModifyRolePrivileges(privileges []IRolePrivilege) (errs []error) {
	var link LinkKey[int64, int64]
	if privileges != nil {
		if cem.rolePrivileges.newLinks == nil {
			cem.rolePrivileges.newLinks = make(map[LinkKey[int64, int64]]IRolePrivilege)
		}
		for _, rp := range privileges {
			link.V1 = rp.RoleId()
			link.V2 = rp.ManagedNodeId()
			cem.rolePrivileges.newLinks[link] = rp
		}
	}
	return nil
}

func (cem *proxyEnterpriseManagement) ModifyManagedNodes(managedNodesToAdd []IManagedNode, managedNodesToUpdate []IManagedNode, managedNodesToRemove []IManagedNode) (errs []error) {
	var link LinkKey[int64, int64]
	if managedNodesToAdd != nil || managedNodesToUpdate != nil {
		if cem.managedNodes.newLinks == nil {
			cem.managedNodes.newLinks = make(map[LinkKey[int64, int64]]IManagedNode)
		}
		for _, mn := range managedNodesToAdd {
			link.V1 = mn.RoleId()
			link.V2 = mn.ManagedNodeId()
			if cem.managedNodes.removedLinks != nil {
				if cem.managedNodes.removedLinks.Has(link) {
					cem.managedNodes.removedLinks.Delete(link)
				}
			}
			cem.managedNodes.newLinks[link] = mn
		}
		for _, mn := range managedNodesToUpdate {
			link.V1 = mn.RoleId()
			link.V2 = mn.ManagedNodeId()
			if cem.managedNodes.removedLinks != nil {
				if cem.managedNodes.removedLinks.Has(link) {
					cem.managedNodes.removedLinks.Delete(link)
				}
			}
			cem.managedNodes.newLinks[link] = mn
		}
	}
	if managedNodesToRemove != nil {
		if cem.managedNodes.removedLinks == nil {
			cem.managedNodes.removedLinks = api.NewSet[LinkKey[int64, int64]]()
		}
		for _, mn := range managedNodesToRemove {
			link.V1 = mn.RoleId()
			link.V2 = mn.ManagedNodeId()
			if cem.managedNodes.newLinks != nil {
				delete(cem.managedNodes.newLinks, link)
			}
			var origManagedNode = cem.managedNodes.origLinks.GetLink(mn.RoleId(), mn.ManagedNodeId())
			if origManagedNode != nil {
				cem.managedNodes.removedLinks.Add(link)
			}
		}
	}
	return
}

func (cem *proxyEnterpriseManagement) ModifyRoleEnforcements(enforcementsToSet []IRoleEnforcement) (errs []error) {
	if cem.roleEnforcements.newLinks == nil {
		cem.roleEnforcements.newLinks = make(map[LinkKey[int64, string]]IRoleEnforcement)
	}
	for _, e := range enforcementsToSet {
		var link = LinkKey[int64, string]{
			V1: e.RoleId(),
			V2: e.EnforcementType(),
		}
		cem.roleEnforcements.newLinks[link] = e
	}
	return
}

func (cem *proxyEnterpriseManagement) Commit() (errs []error) {
	var er1 []error
	if cem.nodes.newEntities != nil || cem.nodes.removedEntities != nil {
		var toAdd, toUpdate []INode
		var toDelete []int64
		if cem.nodes.newEntities != nil {
			for _, v := range cem.nodes.newEntities {
				var origNode = cem.enterpriseManagement.EnterpriseData().Nodes().GetEntity(v.NodeId())
				if origNode == nil {
					toAdd = append(toAdd, v)
				} else {
					toUpdate = append(toUpdate, v)
				}
			}
		}
		if cem.nodes.removedEntities != nil {
			toDelete = cem.nodes.removedEntities.ToArray()
		}
		if len(toAdd) > 0 {
			sort.Slice(toAdd, func(i, j int) bool {
				var a = toAdd[i]
				var b = toAdd[j]
				return a.NodeId() < b.NodeId()
			})
		}
		if er1 = cem.enterpriseManagement.ModifyNodes(toAdd, toUpdate, toDelete); len(er1) > 0 {
			errs = append(errs, er1...)
		}
	}

	// TODO Call underlying modifies

	return
}
