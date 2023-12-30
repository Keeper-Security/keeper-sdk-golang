package database

type SsoToken struct {
	Command      string `json:"command"`
	Result       string `json:"result"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	NewPassword  string `json:"new_password"`
	ProviderName string `json:"provider_name"`
	SessionId    string `json:"session_id"`
	LoginToken   string `json:"login_token"`
}
