package api

type IKeeperCommand interface {
	CommandName() string
	GetAuthorizedCommand() *AuthorizedCommand
}

type IKeeperResponse interface {
	GetKeeperApiResponse() *KeeperApiResponse
}

type KeeperApiCommand struct {
	Command       string `json:"command"`
	Locale        string `json:"locale"`
	ClientVersion string `json:"client_version"`
}

type KeeperApiResponse struct {
	Result     string `json:"result"`
	ResultCode string `json:"result_code"`
	Message    string `json:"message"`
	Command    string `json:"command"`
}

func (rs *KeeperApiResponse) GetKeeperApiResponse() *KeeperApiResponse {
	return rs
}

func (rs *KeeperApiResponse) IsSuccess() bool {
	return rs.Result == "success"
}

type KeeperApiErrorResponse struct {
	KeeperApiResponse
	Error          string `json:"error"`
	KeyId          int32  `json:"key_id"`
	RegionHost     string `json:"region_host"`
	AdditionalInfo string `json:"additional_info"`
}
type AuthorizedCommand struct {
	KeeperApiCommand
	SessionToken string `json:"session_token"`
	Username     string `json:"username"`
}

func (command *AuthorizedCommand) GetAuthorizedCommand() *AuthorizedCommand {
	return command
}
