package deployment

import (
	"os/user"
	"testing"
)

func TestNativeWorkerIdentityRejectsRootOrOtherGroups(t *testing.T) {
	for _, mutation := range []string{"valid", "root uid", "root gid", "regular user", "different name", "different primary", "extra group", "home", "noncanonical"} {
		t.Run(mutation, func(t *testing.T) {
			account := &user.User{Username: nativeWorkerName, Uid: "991", Gid: "992", HomeDir: "/nonexistent"}
			group := &user.Group{Name: nativeWorkerName, Gid: "992"}
			groups := []string{"992"}
			switch mutation {
			case "root uid":
				account.Uid = "0"
			case "root gid":
				account.Gid, group.Gid, groups[0] = "0", "0", "0"
			case "regular user":
				account.Uid = "1000"
			case "different name":
				group.Name = "root"
			case "different primary":
				account.Gid = "993"
			case "extra group":
				groups = append(groups, "0")
			case "home":
				account.HomeDir = "/root"
			case "noncanonical":
				account.Uid = "0991"
			}
			uid, gid, err := checkNativeWorkerIDs(account, group, groups)
			if (err == nil) != (mutation == "valid") || (err == nil && (uid != 991 || gid != 992)) {
				t.Fatalf("identity=%d:%d err=%v", uid, gid, err)
			}
		})
	}
}
