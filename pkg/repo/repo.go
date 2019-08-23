package repo

import (
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"os/exec"
	"strings"
)

func Push(root string, debug bool) (err error) {
	cmd := exec.Command("/usr/bin/git", "add", ".")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return
	}
	if debug {
		log.Debugf("exec %s:\n%s", cmd.Args, string(out))
	}

	cmd = exec.Command("/usr/bin/git", "commit", "-am", uuid.New().String())
	cmd.Dir = root
	out, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	if debug {
		log.Debugf("exec %s:\n%s", cmd.Args, string(out))
	}

	cmd = exec.Command("/usr/bin/git", "push")
	cmd.Dir = root
	out, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	if debug {
		log.Debugf("exec %s:\n%s", cmd.Args, string(out))
	}
	return
}

func Pull(root string, debug bool) (updated bool, err error) {
	cmd := exec.Command("/usr/bin/git", "pull")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return
	}
	if debug {
		log.Debugf("exec %s:\n%s", cmd.Args, string(out))
	}

	if strings.Contains(string(out), "Already up to date.") {
		updated = true
	}
	return
}
