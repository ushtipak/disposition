package repo

import (
	"github.com/golang/glog"
	"github.com/google/uuid"
	"os/exec"
	"strings"
)

func Push(root string) (err error) {
	cmd := exec.Command("/usr/bin/git", "add", ".")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return
	}
	glog.V(2).Infof("exec %s:\n%s", cmd.Args, string(out))

	cmd = exec.Command("/usr/bin/git", "commit", "-am", uuid.New().String())
	cmd.Dir = root
	out, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	glog.V(2).Infof("exec %s:\n%s", cmd.Args, string(out))

	cmd = exec.Command("/usr/bin/git", "push")
	cmd.Dir = root
	out, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	glog.V(2).Infof("exec %s:\n%s", cmd.Args, string(out))
	return
}

func Pull(root string) (updated bool, err error) {
	cmd := exec.Command("/usr/bin/git", "pull")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return
	}
	glog.V(2).Infof("exec %s:\n%s", cmd.Args, string(out))

	if strings.Contains(string(out), "Already up to date.") {
		updated = true
	}
	return
}
