package json_commands

import (
	"github.com/keeper-security/keeper-sdk-golang/api"
)

type ChangeMasterPasswordCommand struct {
	api.AuthorizedCommand
	AuthVerifier     string `json:"auth_verifier"`
	EncryptionParams string `json:"encryption_params"`
}

func (c *ChangeMasterPasswordCommand) CommandName() string {
	return "change_master_password"
}

type ShareAccountCommand struct {
	api.AuthorizedCommand
	ToRoleId    int64  `json:"to_role_id"`
	TransferKey string `json:"transfer_key"`
}

func (c *ShareAccountCommand) CommandName() string {
	return "share_account"
}

type ExecuteCommand struct {
	api.AuthorizedCommand
	Requests []api.IKeeperCommand `json:"requests"`
}

func (c *ExecuteCommand) CommandName() string {
	return "execute"
}

type ExecuteResponse struct {
	api.KeeperApiResponse
	Responses []*api.KeeperApiResponse `json:"results"`
}

type TeamGetKeysCommand struct {
	api.AuthorizedCommand
	Teams []string `json:"teams"`
}

func (c *TeamGetKeysCommand) CommandName() string {
	return "team_get_keys"
}

type TeamKeyResponse struct {
	TeamId string `json:"team_id"`
	Key    string `json:"key"`
	Type   int    `json:"type"`
	Result string `json:"result"`
}
type TeamGetKeysResponse struct {
	api.KeeperApiResponse
	Keys []TeamKeyResponse `json:"keys"`
}
