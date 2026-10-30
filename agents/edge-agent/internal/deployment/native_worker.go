package deployment

import (
	"errors"
	"os/user"
	"strconv"
)

// nativeWorkerName is the native OpenResty worker account and group.
const nativeWorkerName = "cdnca-runtime"

var errNativeWorker = errors.New("native worker identity is unsafe")

// nativeWorkerIDs looks up the native worker account. The installer
// additionally verifies nologin, a locked password and unique account/group
// membership; the identity used by initgroups is rechecked here at runtime.
func nativeWorkerIDs() (uint32, uint32, error) {
	account, err := user.Lookup(nativeWorkerName)
	if err != nil {
		return 0, 0, errNativeWorker
	}
	group, err := user.LookupGroup(nativeWorkerName)
	if err != nil {
		return 0, 0, errNativeWorker
	}
	groups, err := account.GroupIds()
	if err != nil {
		return 0, 0, errNativeWorker
	}
	return checkNativeWorkerIDs(account, group, groups)
}

func checkNativeWorkerIDs(account *user.User, group *user.Group, groups []string) (uint32, uint32, error) {
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(group.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || uid > 999 || gid == 0 || gid > 999 ||
		account.Username != nativeWorkerName || group.Name != nativeWorkerName || account.Gid != group.Gid ||
		account.HomeDir != "/nonexistent" || account.Uid != strconv.FormatUint(uid, 10) || group.Gid != strconv.FormatUint(gid, 10) ||
		len(groups) != 1 || groups[0] != group.Gid {
		return 0, 0, errNativeWorker
	}
	return uint32(uid), uint32(gid), nil
}
