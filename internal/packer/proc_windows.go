//go:build windows

package packer

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// setProcAttrs starts packer in a new process group so it can receive
// CTRL_BREAK without affecting the service.
func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// interrupt sends CTRL_BREAK to packer's process group. A service has no
// console, in which case this fails and packer is killed instead.
func interrupt(cmd *exec.Cmd) error {
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid)); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}

func killTree(*exec.Cmd) {}
