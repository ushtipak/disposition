package repo

import (
	"github.com/golang/glog"
	"github.com/google/uuid"
	"gopkg.in/src-d/go-git.v4"
	"os/exec"
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
	r, err := git.PlainOpen(root)
	if err != nil {
		return
	}
	w, err := r.Worktree()
	if err != nil {
		return
	}

	err = w.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil {
		if err == git.NoErrAlreadyUpToDate {
			return updated, nil
		} else {
			return
		}
	}

	updated = true
	return
}
