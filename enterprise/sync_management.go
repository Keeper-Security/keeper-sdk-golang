package enterprise

import (
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/json_commands"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_enterprise"
	"go.uber.org/zap"
	"sync"
)

func NewSyncEnterpriseManagement(loader IEnterpriseLoader) IEnterpriseManagement {
	var m = &syncEnterpriseManagement{
		loader: loader,
	}
	if loader.Storage() != nil {
		var err error
		if m.enterpriseIds, err = loader.Storage().EnterpriseIds(); err != nil {
			api.GetLogger().Debug("Error loading enterprise IDs from storage", zap.Error(err))
		}
	}
	return m
}

type syncEnterpriseManagement struct {
	loader        IEnterpriseLoader
	enterpriseIds []int64
	lock          sync.Mutex
}

func (sem *syncEnterpriseManagement) EnterpriseData() IEnterpriseData {
	return sem.loader.EnterpriseData()
}

func (sem *syncEnterpriseManagement) GetEnterpriseId() (id int64, err error) {
	var numRequested = 2
	if sem.loader.Storage() != nil {
		numRequested = 10
	}

	sem.lock.Lock()
	defer sem.lock.Unlock()
	if len(sem.enterpriseIds) == 0 {
		var ids []int64
		if ids, err = GetEnterpriseIds(sem.loader.KeeperAuth(), numRequested); err != nil {
			return
		}
		sem.enterpriseIds = append(sem.enterpriseIds, ids...)
	}
	id = sem.enterpriseIds[0]
	sem.enterpriseIds = sem.enterpriseIds[1:]
	return
}

func (sem *syncEnterpriseManagement) ModifyNodes(nodesToAdd []INode, nodesToUpdate []INode, nodesToDelete []int64) (errs []error) {
	var requests []api.IKeeperCommand
	requests, errs = prepareNodeRequests(sem.loader, nodesToAdd, nodesToUpdate, nodesToDelete)

	var err error
	var rss []*api.KeeperApiResponse
	if rss, err = sem.loader.KeeperAuth().ExecuteBatch(requests); err != nil {
		errs = append(errs, err)
		return
	}

	for i, x := range rss {
		if !x.IsSuccess() {
			var rq = requests[i]
			var nodeId int64
			switch r := rq.(type) {
			case *json_commands.EnterpriseNodeDeleteCommand:
				nodeId = r.NodeId
			case *json_commands.EnterpriseNodeAddCommand:
				nodeId = r.NodeId
			case *json_commands.EnterpriseNodeUpdateCommand:
				nodeId = r.NodeId
			}
			var message = x.Message
			if nodeId > 0 {
				message += fmt.Sprintf("; command=\"%s\"; nodeID=%d", rq.CommandName(), nodeId)
			}
			err = api.NewKeeperApiError(x.ResultCode, message)
			errs = append(errs, err)
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}
	return
}

func (sem *syncEnterpriseManagement) ModifyTeams(teamsToAdd []ITeam, teamsToUpdate []ITeam, teamsToDelete []string) (errs []error) {
	var requests []api.IKeeperCommand
	requests, errs = prepareTeamRequests(sem.loader, teamsToAdd, teamsToUpdate, teamsToDelete)

	var err error
	var rss []*api.KeeperApiResponse
	if rss, err = sem.loader.KeeperAuth().ExecuteBatch(requests); err != nil {
		errs = append(errs, err)
		return
	}

	for i, x := range rss {
		if !x.IsSuccess() {
			var rq = requests[i]
			var teamUid string
			switch r := rq.(type) {
			case *json_commands.EnterpriseTeamDeleteCommand:
				teamUid = r.TeamUid
			case *json_commands.EnterpriseTeamAddCommand:
				teamUid = r.TeamUid
			case *json_commands.EnterpriseTeamUpdateCommand:
				teamUid = r.TeamUid
			}
			var message = x.Message
			if len(teamUid) > 0 {
				message += fmt.Sprintf("; teamUID=\"%s\"", teamUid)
			}
			err = api.NewKeeperApiError(x.ResultCode, message)
			errs = append(errs, err)
			continue
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}
	return
}

func (sem *syncEnterpriseManagement) ModifyRoles(rolesToAdd []IRole, rolesToUpdate []IRole, rolesToDelete []int64) (errs []error) {
	var requests []api.IKeeperCommand
	requests, errs = prepareRoleRequests(sem.loader, rolesToAdd, rolesToUpdate, rolesToDelete)

	var err error
	var rss []*api.KeeperApiResponse
	if rss, err = sem.loader.KeeperAuth().ExecuteBatch(requests); err != nil {
		errs = append(errs, err)
		return
	}

	for i, x := range rss {
		if !x.IsSuccess() {
			var rq = requests[i]
			var roleId int64
			switch r := rq.(type) {
			case *json_commands.EnterpriseRoleDeleteCommand:
				roleId = r.RoleId
			case *json_commands.EnterpriseRoleAddCommand:
				roleId = r.RoleId
			case *json_commands.EnterpriseRoleUpdateCommand:
				roleId = r.RoleId
			}
			var message = x.Message
			if roleId > 0 {
				message += fmt.Sprintf("; roleID=\"%d\"", roleId)
			}
			err = api.NewKeeperApiError(x.ResultCode, message)
			errs = append(errs, err)
			continue
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}
	return
}

func (sem *syncEnterpriseManagement) ModifyTeamUsers(teamUsersToAdd []ITeamUser, teamUsersToRemove []ITeamUser) (errs []error) {
	var jsonRequests []api.IKeeperCommand
	jsonRequests, errs = prepareTeamUserRequests(sem.loader, teamUsersToAdd, teamUsersToRemove)

	var err error
	if len(jsonRequests) > 0 {
		var rss []*api.KeeperApiResponse
		if rss, err = sem.loader.KeeperAuth().ExecuteBatch(jsonRequests); err != nil {
			errs = append(errs, err)
			return
		}
		for i, x := range rss {
			if !x.IsSuccess() {
				var rq = jsonRequests[i]
				var teamUid string
				var userId int64
				switch r := rq.(type) {
				case *json_commands.EnterpriseTeamUserAddCommand:
					teamUid = r.TeamUid
					userId = r.EnterpriseUserId
				case *json_commands.EnterpriseTeamUserUpdateCommand:
					teamUid = r.TeamUid
					userId = r.EnterpriseUserId
				case *json_commands.EnterpriseTeamUserRemoveCommand:
					teamUid = r.TeamUid
					userId = r.EnterpriseUserId
				default:
					continue
				}
				var message = x.Message
				if userId > 0 {
					message += fmt.Sprintf("; teamUID=\"%s\"; UserID=\"%d\"", teamUid, userId)
				}
				err = api.NewKeeperApiError(x.ResultCode, message)
				errs = append(errs, err)
				continue
			}
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}

	return
}

func (sem *syncEnterpriseManagement) ModifyRoleUsers(roleUsersToAdd []IRoleUser, roleUsersToRemove []IRoleUser) (errs []error) {
	var jsonRequests []api.IKeeperCommand
	jsonRequests, errs = prepareRoleUserRequests(sem.loader, roleUsersToAdd, roleUsersToRemove)

	var err error
	if len(jsonRequests) > 0 {
		var rss []*api.KeeperApiResponse
		if rss, err = sem.loader.KeeperAuth().ExecuteBatch(jsonRequests); err != nil {
			errs = append(errs, err)
			return
		}
		for i, x := range rss {
			if !x.IsSuccess() {
				var rq = jsonRequests[i]
				var roleId int64
				var userId int64
				switch r := rq.(type) {
				case *json_commands.EnterpriseRoleUserAddCommand:
					roleId = r.RoleId
					userId = r.EnterpriseUserId
				case *json_commands.EnterpriseRoleUserRemoveCommand:
					roleId = r.RoleId
					userId = r.EnterpriseUserId
				default:
					continue
				}
				var message = x.Message
				if userId > 0 {
					message += fmt.Sprintf("; roleID=\"%d\"; UserID=\"%d\"", roleId, userId)
				}
				err = api.NewKeeperApiError(x.ResultCode, message)
				errs = append(errs, err)
				continue
			}
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}

	return
}

func (sem *syncEnterpriseManagement) ModifyRoleTeams(roleTeamsToAdd []IRoleTeam, roleTeamsToRemove []IRoleTeam) (errs []error) {
	var err error
	var roleTeams = sem.loader.EnterpriseData().RoleTeams()
	var managedNodes = sem.loader.EnterpriseData().ManagedNodes()
	var toAdd []*proto_enterprise.RoleTeam
	var toRemove []*proto_enterprise.RoleTeam
	var rt IRoleTeam

	for _, rt = range roleTeamsToAdd {
		var isAdminRole = false
		managedNodes.GetLinksBySubject(rt.RoleId(), func(x IManagedNode) bool {
			isAdminRole = true
			return false
		})
		if isAdminRole {
			errs = append(errs, fmt.Errorf("role-team: cannot add team to admin role. RoleID=\"%d\"", rt.RoleId()))
			continue
		}

		var crt = roleTeams.GetLink(rt.RoleId(), rt.TeamUid())
		if crt == nil {
			toAdd = append(toAdd, &proto_enterprise.RoleTeam{
				RoleId:  rt.RoleId(),
				TeamUid: api.Base64UrlDecode(rt.TeamUid()),
			})
		}
	}
	for _, rt = range roleTeamsToRemove {
		var crt = roleTeams.GetLink(rt.RoleId(), rt.TeamUid())
		if crt != nil {
			toRemove = append(toRemove, &proto_enterprise.RoleTeam{
				RoleId:  rt.RoleId(),
				TeamUid: api.Base64UrlDecode(rt.TeamUid()),
			})
		}
	}

	for len(toAdd) > 0 {
		var rq = &proto_enterprise.RoleTeams{
			RoleTeam: toAdd[:99],
		}
		toAdd = toAdd[99:]
		if err = sem.loader.KeeperAuth().ExecuteAuthRest("enterprise/role_team_add", rq, nil); err != nil {
			errs = append(errs, err)
		}
	}
	for len(toRemove) > 0 {
		var rq = &proto_enterprise.RoleTeams{
			RoleTeam: toRemove[:99],
		}
		toRemove = toRemove[99:]
		if err = sem.loader.KeeperAuth().ExecuteAuthRest("enterprise/role_team_remove", rq, nil); err != nil {
			errs = append(errs, err)
		}
	}
	return
}

func (sem *syncEnterpriseManagement) ModifyRolePrivileges(privileges []IRolePrivilege) (errs []error) {
	var jsonRequests []api.IKeeperCommand
	jsonRequests, errs = prepareRolePrivilegesRequests(sem.loader, privileges)

	var err error
	if len(jsonRequests) > 0 {
		var rss []*api.KeeperApiResponse
		if rss, err = sem.loader.KeeperAuth().ExecuteBatch(jsonRequests); err != nil {
			errs = append(errs, err)
			return
		}
		for i, x := range rss {
			if !x.IsSuccess() {
				var rq = jsonRequests[i]
				var roleId int64
				var managedNodeId int64
				var privilege string
				switch r := rq.(type) {
				case *json_commands.ManagedNodePrivilegeAddCommand:
					roleId = r.RoleId
					managedNodeId = r.ManagedNodeId
					privilege = r.Privilege
				case *json_commands.ManagedNodePrivilegeRemoveCommand:
					roleId = r.RoleId
					managedNodeId = r.ManagedNodeId
					privilege = r.Privilege
				default:
					continue
				}
				var message = x.Message
				if roleId > 0 {
					message += fmt.Sprintf("; roleID=\"%d\"; ManagedNodeID=\"%d\"; Privilege=\"%s\"", roleId, managedNodeId, privilege)
				}
				err = api.NewKeeperApiError(x.ResultCode, message)
				errs = append(errs, err)
				continue
			}
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}

	return
}

func (sem *syncEnterpriseManagement) ModifyManagedNodes(managedNodesToAdd []IManagedNode, managedNodesToUpdate []IManagedNode, managedNodesToRemove []IManagedNode) (errs []error) {
	var jsonRequests []api.IKeeperCommand
	jsonRequests, errs = prepareManagedNodesRequests(sem.loader, managedNodesToAdd, managedNodesToUpdate, managedNodesToRemove)

	var err error
	if len(jsonRequests) > 0 {
		var rss []*api.KeeperApiResponse
		if rss, err = sem.loader.KeeperAuth().ExecuteBatch(jsonRequests); err != nil {
			errs = append(errs, err)
			return
		}
		for i, x := range rss {
			if !x.IsSuccess() {
				var rq = jsonRequests[i]
				var roleId int64
				var managedNodeId int64
				switch r := rq.(type) {
				case *json_commands.RoleManagedNodeAddCommand:
					roleId = r.RoleId
					managedNodeId = r.ManagedNodeId
				case *json_commands.RoleManagedNodeUpdateCommand:
					roleId = r.RoleId
					managedNodeId = r.ManagedNodeId
				case *json_commands.RoleManagedNodeRemoveCommand:
					roleId = r.RoleId
					managedNodeId = r.ManagedNodeId
				default:
					continue
				}
				var message = x.Message
				if roleId > 0 {
					message += fmt.Sprintf("; roleID=\"%d\"; ManagedNodeID=\"%d\"", roleId, managedNodeId)
				}
				err = api.NewKeeperApiError(x.ResultCode, message)
				errs = append(errs, err)
				continue
			}
		}
	}

	if err = sem.loader.Load(); err != nil {
		errs = append(errs, err)
	}

	return
}

func (sem *syncEnterpriseManagement) ModifyRoleEnforcements(enforcementsToSet []IRoleEnforcement) (errs []error) {
	var jsonRequests []api.IKeeperCommand
	var err error
	jsonRequests, errs = prepareRoleEnforcementsRequests(sem.loader, enforcementsToSet)
	if len(jsonRequests) > 0 {
		var rss []*api.KeeperApiResponse
		if rss, err = sem.loader.KeeperAuth().ExecuteBatch(jsonRequests); err != nil {
			errs = append(errs, err)
			return
		}
		for i, x := range rss {
			if !x.IsSuccess() {
				var rq = jsonRequests[i]
				var roleId int64
				var enf string
				switch r := rq.(type) {
				case *json_commands.RoleEnforcementAddCommand:
					roleId = r.RoleId
					enf = r.Enforcement
				case *json_commands.RoleEnforcementUpdateCommand:
					roleId = r.RoleId
					enf = r.Enforcement
				case *json_commands.RoleEnforcementRemoveCommand:
					roleId = r.RoleId
					enf = r.Enforcement
				default:
					continue
				}
				var message = x.Message
				if roleId > 0 {
					message += fmt.Sprintf("; roleID=\"%d\"; Enforcement=\"%s\"", roleId, enf)
				}
				err = api.NewKeeperApiError(x.ResultCode, message)
				errs = append(errs, err)
				continue
			}
		}
	}
	return
}

func (sem *syncEnterpriseManagement) Commit() (errs []error) {
	var storage = sem.loader.Storage()
	if storage == nil {
		return
	}
	if len(sem.enterpriseIds) > 0 {
		sem.lock.Lock()
		defer sem.lock.Unlock()
		var err error
		if err = storage.SetEnterpriseIds(sem.enterpriseIds); err != nil {
			errs = append(errs, err)
		}
		sem.enterpriseIds = nil
	}
	return
}
