package json_commands

import (
	"github.com/keeper-security/keeper-sdk-golang/api"
)

type EnterpriseAllocateIdsCommand struct {
	api.AuthorizedCommand
	NumberRequested int `json:"number_requested"`
}

func (c *EnterpriseAllocateIdsCommand) CommandName() string {
	return "enterprise_allocate_ids"
}

type EnterpriseAllocateIdsResponse struct {
	api.KeeperApiResponse
	NumberAllocated int   `json:"number_allocated"`
	BaseId          int64 `json:"base_id"`
}

type EnterpriseNode struct {
	NodeId             int64   `json:"node_id"`
	ParentId           int64   `json:"parent_id"`
	EncryptedData      string  `json:"encrypted_data"`
	RestrictVisibility *string `json:"restrict_visibility,omitempty"`
}
type EnterpriseNodeAddCommand struct {
	api.AuthorizedCommand
	EnterpriseNode
}

func (c *EnterpriseNodeAddCommand) CommandName() string {
	return "node_add"
}

type EnterpriseNodeUpdateCommand struct {
	api.AuthorizedCommand
	EnterpriseNode
}

func (c *EnterpriseNodeUpdateCommand) CommandName() string {
	return "node_update"
}

type EnterpriseNodeDeleteCommand struct {
	api.AuthorizedCommand
	NodeId int64 `json:"node_id"`
}

func (c *EnterpriseNodeDeleteCommand) CommandName() string {
	return "node_delete"
}

type EnterpriseTeam struct {
	TeamUid       string `json:"team_uid"`
	TeamName      string `json:"team_name"`
	NodeId        *int64 `json:"node_id,omitempty"`
	RestrictShare bool   `json:"restrict_share"`
	RestrictEdit  bool   `json:"restrict_edit"`
	RestrictView  bool   `json:"restrict_view"`
}

type EnterpriseTeamAddCommand struct {
	api.AuthorizedCommand
	EnterpriseTeam
	PublicKey        string `json:"public_key"`
	PrivateKey       string `json:"private_key"`
	TeamKey          string `json:"team_key"`
	ManageOnly       bool   `json:"manage_only"`
	EncryptedTeamKey string `json:"encrypted_team_key"`
}

func (c *EnterpriseTeamAddCommand) CommandName() string {
	return "team_add"
}

type EnterpriseTeamUpdateCommand struct {
	api.AuthorizedCommand
	EnterpriseTeam
}

func (c *EnterpriseTeamUpdateCommand) CommandName() string {
	return "team_update"
}

type EnterpriseTeamDeleteCommand struct {
	api.AuthorizedCommand
	TeamUid string `json:"team_uid"`
}

func (c *EnterpriseTeamDeleteCommand) CommandName() string {
	return "team_delete"
}

type EnterpriseRole struct {
	RoleId         int64  `json:"role_id"`
	EncryptedData  string `json:"encrypted_data"`
	NodeId         int64  `json:"node_id"`
	VisibleBelow   *bool  `json:"visible_below,omitempty"`
	NewUserInherit *bool  `json:"new_user_inherit,omitempty"`
}
type EnterpriseRoleAddCommand struct {
	api.AuthorizedCommand
	EnterpriseRole
}

func (c *EnterpriseRoleAddCommand) CommandName() string {
	return "role_add"
}

type EnterpriseRoleUpdateCommand struct {
	api.AuthorizedCommand
	EnterpriseRole
}

func (c *EnterpriseRoleUpdateCommand) CommandName() string {
	return "role_update"
}

type EnterpriseRoleDeleteCommand struct {
	api.AuthorizedCommand
	RoleId int64 `json:"role_id"`
}

func (c *EnterpriseRoleDeleteCommand) CommandName() string {
	return "role_delete"
}

type EnterpriseTeamUser struct {
	TeamUid          string `json:"team_uid"`
	EnterpriseUserId int64  `json:"enterprise_user_id"`
}

type EnterpriseTeamUserAddCommand struct {
	api.AuthorizedCommand
	EnterpriseTeamUser
	TeamKey  string `json:"team_key"`
	UserType int32  `json:"user_type"`
}

func (c *EnterpriseTeamUserAddCommand) CommandName() string {
	return "team_enterprise_user_add"
}

type EnterpriseTeamUserUpdateCommand struct {
	api.AuthorizedCommand
	EnterpriseTeamUser
	UserType int32 `json:"user_type"`
}

func (c *EnterpriseTeamUserUpdateCommand) CommandName() string {
	return "team_enterprise_user_update"
}

type EnterpriseTeamUserRemoveCommand struct {
	api.AuthorizedCommand
	EnterpriseTeamUser
}

func (c *EnterpriseTeamUserRemoveCommand) CommandName() string {
	return "team_enterprise_user_remove"
}

type EnterpriseRoleUser struct {
	RoleId           int64 `json:"role_id"`
	EnterpriseUserId int64 `json:"enterprise_user_id"`
}
type EnterpriseRoleUserAddCommand struct {
	api.AuthorizedCommand
	EnterpriseRoleUser
	TreeKey      string `json:"tree_key"`
	RoleAdminKey string `json:"role_admin_key"`
}

func (c *EnterpriseRoleUserAddCommand) CommandName() string {
	return "role_user_add"
}

type EnterpriseRoleUserRemoveCommand struct {
	api.AuthorizedCommand
	EnterpriseRoleUser
}

func (c *EnterpriseRoleUserRemoveCommand) CommandName() string {
	return "role_user_remove"
}

type RoleUserKey struct {
	EnterpriseUserId int64  `json:"enterprise_user_id"`
	RoleKey          string `json:"role_key"`
}

type ManagedNode struct {
	RoleId        int64 `json:"role_id"`
	ManagedNodeId int64 `json:"managed_node_id"`
}

type RoleManagedNodeAddCommand struct {
	api.AuthorizedCommand
	ManagedNode
	CascadeNodeManagement bool           `json:"cascade_node_management"`
	TreeKeys              []*RoleUserKey `json:"role_keys"`
}

func (c *RoleManagedNodeAddCommand) CommandName() string {
	return "role_managed_node_add"
}

type RoleManagedNodeUpdateCommand struct {
	api.AuthorizedCommand
	ManagedNode
	CascadeNodeManagement bool `json:"cascade_node_management"`
}

func (c *RoleManagedNodeUpdateCommand) CommandName() string {
	return "role_managed_node_update"
}

type RoleManagedNodeRemoveCommand struct {
	api.AuthorizedCommand
	ManagedNode
}

func (c *RoleManagedNodeRemoveCommand) CommandName() string {
	return "role_managed_node_remove"
}

type ManagedNodePrivilege struct {
	ManagedNode
	Privilege string `json:"privilege"`
}
type ManagedNodePrivilegeAddCommand struct {
	api.AuthorizedCommand
	ManagedNodePrivilege
	RolePublicKey         *string        `json:"role_public_key,omitempty"`
	RolePrivateKey        *string        `json:"role_private_key,omitempty"`
	RoleKeyEncWithTreeKey *string        `json:"role_key_enc_with_tree_key,omitempty"`
	RoleKeys              []*RoleUserKey `json:"role_keys,omitempty"`
}

func (c *ManagedNodePrivilegeAddCommand) CommandName() string {
	return "managed_node_privilege_add"
}

type ManagedNodePrivilegeRemoveCommand struct {
	api.AuthorizedCommand
	ManagedNodePrivilege
}

func (c *ManagedNodePrivilegeRemoveCommand) CommandName() string {
	return "managed_node_privilege_remove"
}

type RoleEnforcement struct {
	RoleId      int64  `json:"role_id"`
	Enforcement string `json:"enforcement"`
}

type RoleEnforcementAddCommand struct {
	api.AuthorizedCommand
	RoleEnforcement
	Value interface{} `json:"value,omitempty"`
}

func (c *RoleEnforcementAddCommand) CommandName() string {
	return "role_enforcement_add"
}

type RoleEnforcementUpdateCommand struct {
	api.AuthorizedCommand
	RoleEnforcement
	Value interface{} `json:"value,omitempty"`
}

func (c *RoleEnforcementUpdateCommand) CommandName() string {
	return "role_enforcement_update"
}

type RoleEnforcementRemoveCommand struct {
	api.AuthorizedCommand
	RoleEnforcement
}

func (c *RoleEnforcementRemoveCommand) CommandName() string {
	return "role_enforcement_remove"
}
