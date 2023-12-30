package auth

import (
	"crypto/ecdh"
	"crypto/rsa"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"github.com/keeper-security/keeper-sdk-golang/internal/json_commands"
	"github.com/keeper-security/keeper-sdk-golang/internal/proto_auth"
)

type PublicKeys struct {
	RsaPublicKey *rsa.PublicKey
	EcPublicKey  *ecdh.PublicKey
}

func GetUserPublicKeys(keeperAuth IKeeperAuth, userKeys map[string]*PublicKeys) (errs []error) {
	if len(userKeys) == 0 {
		return
	}

	var rq = new(proto_auth.GetPublicKeysRequest)
	for k := range userKeys {
		rq.Usernames = append(rq.Usernames, k)
	}

	var err error
	var rs = new(proto_auth.GetPublicKeysResponse)
	if err = keeperAuth.ExecuteAuthRest("vault/get_public_keys", rq, rs); err != nil {
		return
	}
	for _, v := range rs.KeyResponses {
		if len(v.PublicEccKey) > 0 || len(v.PublicKey) > 0 {
			var pk = new(PublicKeys)
			if len(v.PublicEccKey) > 0 {
				var ecpk *ecdh.PublicKey
				if ecpk, err = api.LoadEcPublicKey(v.PublicEccKey); err == nil {
					pk.EcPublicKey = ecpk
				} else {
					errs = append(errs, err)
				}
			}
			if len(v.PublicKey) > 0 {
				var rsapk *rsa.PublicKey
				if rsapk, err = api.LoadRsaPublicKey(v.PublicKey); err == nil {
					pk.RsaPublicKey = rsapk
				} else {
					errs = append(errs, err)
				}
			}
			userKeys[v.Username] = pk
		} else {
			err = api.NewKeeperApiError(v.ErrorCode, v.Message)
			errs = append(errs, err)
		}
	}
	return
}

func GetTeamKeys(keeperAuth IKeeperAuth, teamKeys map[string][]byte) (errs []error) {
	var teamUids []string
	for k, v := range teamKeys {
		if v == nil {
			teamUids = append(teamUids, k)
		}
	}
	var err error
	for len(teamUids) > 0 {
		var chunk = append(([]string)(nil), teamUids[:99]...)
		teamUids = append(([]string)(nil), teamUids[99:]...)
		var rq = &json_commands.TeamGetKeysCommand{
			Teams: chunk,
		}
		var rs = new(json_commands.TeamGetKeysResponse)
		if err = keeperAuth.ExecuteAuthCommand(rq, rs, true); err != nil {
			errs = append(errs, err)
			break
		}
		for _, key := range rs.Keys {
			if len(key.Key) > 0 {
				var keyData = api.Base64UrlDecode(key.Key)
				switch key.Type {
				case 1:
					if keyData, err = api.DecryptAesV1(keyData, keeperAuth.AuthContext().DataKey()); err != nil {
						teamKeys[key.TeamId] = keyData
					} else {
						errs = append(errs, err)
					}
				case 2:
					if keyData, err = api.DecryptRsa(keyData, keeperAuth.AuthContext().RsaPrivateKey()); err != nil {
						teamKeys[key.TeamId] = keyData
					} else {
						errs = append(errs, err)
					}
				}
			} else {
				errs = append(errs, fmt.Errorf("team UID \"%s\" does not exist", key.Result))
			}
		}
	}

	return
}
