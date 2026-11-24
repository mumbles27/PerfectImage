//go:build !windows

package packer

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcAttrs puts packer in its own process group so its plugin
// processes can be cleaned up together.
func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// interrupt asks packer to stop; it then cancels the build and deletes the
// build VM before exiting. The signal goes to the whole process group, like
// Ctrl-C in a terminal: packer runs as a panicwrap parent that discards
// SIGINT and relies on the child (which does the work) receiving it too.
func interrupt(cmd *exec.Cmd) error {
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGINT); err != nil {
		return cmd.Process.Signal(os.Interrupt)
	}
	return nil
}

// killTree kills any process left in packer's process group.
func killTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
