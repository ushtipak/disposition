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

func Pull(root, stateObfuscated string) (ff []string, stateChanged bool, err error) {
	cmd := exec.Command("/usr/bin/git", "pull")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return
	}
	glog.V(2).Infof("exec %s:\n%s", cmd.Args, string(out))

	if !strings.Contains(string(out), "Already up to date.") {
		// TODO: fix issue when there are less then 3 commits
		//       fatal: ambiguous argument 'HEAD^~1': unknown revision or path not in the working tree.
		//       Use '--' to separate paths from revisions, like this:
		//       'git <command> [<revision>...] -- [<file>...]'

		cmd := exec.Command("git", "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD^~1")
		cmd.Dir = root
		out, err = cmd.CombinedOutput()
		if err != nil {
			return
		}
		glog.V(2).Infof("exec %s:\n%s", cmd.Args, string(out))

		for _, file := range strings.Split(string(out), "\n") {
			if strings.TrimSpace(file) != "" {
				f := strings.TrimSpace(file)
				if f == stateObfuscated {
					stateChanged = true
				} else {
					ff = append(ff, f)
				}
			}
		}
	}
	return
}
