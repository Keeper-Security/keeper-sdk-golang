package enterprise

import (
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/api"
	"net"
	"strconv"
	"strings"
)

func ToEnforcementValue(loader IEnterpriseLoader, eType string, eValue string) (value string, shouldRemove bool, err error) {
	if eType == "string" {
		if len(eValue) > 0 {
			value = eValue
		} else {
			shouldRemove = true
		}
	} else if eType == "boolean" {
		if eValue == "true" || eValue == "t" || eValue == "1" {
			value = ""
		} else if eValue == "false" || eValue == "f" || eValue == "0" {
			shouldRemove = true
		} else {
			err = fmt.Errorf("role enforcement invalid boolean value \"%s\"", eValue)
		}
	} else if eType == "long" {
		if _, err = strconv.Atoi(eValue); err == nil {
			value = eValue
		} else {
			err = fmt.Errorf("role enforcement invalid long value \"%s\"", eValue)
		}
	} else if strings.HasPrefix(eType, "ternary_") {
		if eValue == "e" || eValue == "enforce" {
			value = "enforce"
		} else if eValue == "d" || eValue == "disable" {
			value = "disable"
		} else if eValue == "n" || eValue == "null" {
			shouldRemove = true
		} else {
			err = fmt.Errorf("role enforcement invalid ternary value \"%s\"", eValue)
		}
	} else if eType == "two_factor_duration" {
		var is = api.SliceSelect(strings.Split(eValue, ","), func(x string) (r int) {
			x = strings.TrimSpace(x)
			switch x {
			case "9999":
				r = 9999
			case "30":
				r = 30
			case "24":
				r = 24
			case "12":
				r = 12
			default:
				r = 0
			}
			return
		})
		var tfa = api.SliceReduce(is, 0, func(i int, m int) (r int) {
			if i > m {
				return i
			}
			return m
		})
		switch tfa {
		case 0:
			value = "0"
		case 12:
			value = "0,12"
		case 24:
			value = "0,12,24"
		case 30:
			value = "0,12,24,30"
		case 9999:
			value = "0,12,24,30,9999"
		}
	} else if eType == "ip_whitelist" {
		var allResolved = true
		var ipRanges = api.SliceSelect(strings.Split(eValue, ","), func(x string) string {
			x = strings.TrimSpace(x)
			x = strings.ToLower(x)
			return x
		})
		ipRanges = api.SliceSelect(ipRanges, func(x string) string {
			var addrs = api.SliceSelect(strings.Split(x, "-"), func(x string) string {
				x = strings.TrimSpace(x)
				x = strings.ToLower(x)
				return x
			})
			if len(addrs) == 2 {
				var ip1 = net.ParseIP(addrs[0])
				var ip2 = net.ParseIP(addrs[1])
				if ip1 != nil && ip2 != nil {
					return fmt.Sprintf("%s-%s", ip1.String(), ip2.String())
				} else {
					allResolved = false
					err = fmt.Errorf("role enforcement invalid ip_whitelist value \"%s\"", eValue)
				}
			} else if len(addrs) == 1 {
				var ip1 = net.ParseIP(addrs[0])
				if ip1 != nil {
					return fmt.Sprintf("%s-%s", ip1.String(), ip1.String())
				} else {
					var ipn *net.IPNet
					if ip1, ipn, err = net.ParseCIDR(addrs[0]); err == nil {
						var ipStart = ip1.Mask(ipn.Mask)
						var ipEnd = ipStart[:]
						var inb = api.SliceSelect(ipn.Mask, func(x byte) byte {
							return ^x
						})
						if len(ipStart) == len(inb) {
							for i, e := range inb {
								ipEnd[i] |= e
							}
						}
						return fmt.Sprintf("%s-%s", ipStart.String(), ipEnd.String())
					} else {
						allResolved = false
						err = fmt.Errorf("role enforcement invalid ip_whitelist value \"%s\"", eValue)
					}
				}
			}
			return x
		})
		if allResolved {
			value = strings.Join(ipRanges, ",")
		}
	} else if eType == "record_types" { // TODO
		value = eValue
	} else if eType == "account_share" {
		var r IRole
		var roleId int
		if roleId, err = strconv.Atoi(eValue); err == nil {
			if r = loader.EnterpriseData().Roles().GetEntity(int64(roleId)); r != nil {
				var isAdminRole = false
				loader.EnterpriseData().ManagedNodes().GetLinksBySubject(int64(roleId), func(x IManagedNode) bool {
					isAdminRole = true
					return false
				})
				if isAdminRole {
					value = eValue
				} else {
					err = fmt.Errorf("role enforcement \"account_share\" not admin role \"%d\"", roleId)
				}
			} else {
				err = fmt.Errorf("role enforcement \"account_share\" invalid role \"%d\"", roleId)
			}
		} else {
			err = fmt.Errorf("role enforcement invalid account_share value \"%s\"", eValue)
		}
	} else {
		value = eValue
	}
	return
}
