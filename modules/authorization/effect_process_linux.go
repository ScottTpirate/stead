package authorization

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
)

// EffectProcess binds the one in-process execution; it is not a transferable
// worker lease. Restart, fork, restore and another manager cannot consume it.
type EffectProcess struct {
	BootID     string
	PID        int
	StartTicks uint64
	Nonce      string
}

func (EffectProcess) String() string           { return "authorization.effect-process[private]" }
func (process EffectProcess) GoString() string { return process.String() }
func (process EffectProcess) valid() bool {
	return len(process.BootID) == 36 && process.BootID[8] == '-' && process.BootID[13] == '-' &&
		process.BootID[18] == '-' && process.BootID[23] == '-' && effectHex(strings.ReplaceAll(process.BootID, "-", ""), 32) &&
		process.PID > 0 && process.StartTicks > 0 && effectHex(process.Nonce, 32)
}
func readEffectProcess() (EffectProcess, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(boot) > 64 {
		return EffectProcess{}, ErrDenied
	}
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil || len(stat) > 8192 {
		return EffectProcess{}, ErrDenied
	}
	// comm may contain spaces and ')'; fields after its final ')' are fixed.
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return EffectProcess{}, ErrDenied
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) < 20 {
		return EffectProcess{}, ErrDenied
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return EffectProcess{}, ErrDenied
	}
	return EffectProcess{BootID: strings.TrimSpace(string(boot)), PID: os.Getpid(), StartTicks: start}, nil
}
func newEffectProcess() (EffectProcess, error) {
	process, err := readEffectProcess()
	if err != nil {
		return EffectProcess{}, ErrDenied
	}
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return EffectProcess{}, ErrDenied
	}
	process.Nonce = hex.EncodeToString(material[:])
	if !process.valid() {
		return EffectProcess{}, ErrDenied
	}
	return process, nil
}
