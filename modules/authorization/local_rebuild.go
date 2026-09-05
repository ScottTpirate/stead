package authorization

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

const localModuleProxy = "file:///tmp/stead-go-path/pkg/mod/cache/download"

// Hash the entire compiler distribution, not just the go driver and compiler.
// The independent review checks this digest against the pinned upstream archive.
// No executable, standard-library source, assembly input or linker may drift.
func localToolchainDigest(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrDenied
	}
	hash := sha256.New()
	var total int64
	count := 0
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.Type()&os.ModeSymlink != 0 {
			return ErrDenied
		}
		if name == root {
			return nil
		}
		count++
		info, err := entry.Info()
		if err != nil || count > 40000 || (!info.IsDir() && !info.Mode().IsRegular()) || info.Size() > 128<<20 {
			return ErrDenied
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return ErrDenied
		}
		digest := "directory"
		if !info.IsDir() {
			total += info.Size()
			if total > 1<<30 {
				return ErrDenied
			}
			digest, err = localFileDigest(name, 128<<20)
			if err != nil {
				return err
			}
		}
		encoded, _ := json.Marshal(struct {
			Path   string `json:"path"`
			Mode   uint32 `json:"mode"`
			Digest string `json:"digest"`
		}{filepath.ToSlash(relative), uint32(info.Mode().Perm()), digest})
		_, _ = hash.Write(append(encoded, '\n'))
		return nil
	})
	if err != nil || count == 0 {
		return "", ErrDenied
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func localFileDigest(name string, maximum int64) (string, error) {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum || info.Size() < 0 {
		return "", ErrDenied
	}
	file, err := os.Open(name)
	if err != nil {
		return "", ErrDenied
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || n != info.Size() || n > maximum {
		return "", ErrDenied
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// Export every tracked regular blob from the exact commit, verifying archive
// bytes against ls-tree. export-ignore/export-subst attributes therefore cannot
// silently change compiler inputs. Symlinks and submodules are unsupported.
func exportLocalSource(ctx context.Context, repository, revision, destination string) error {
	listed, err := gitLocal(ctx, repository, "ls-tree", "-r", "-z", "--full-tree", revision)
	if err != nil {
		return err
	}
	want := map[string]string{}
	for _, record := range bytes.Split(listed, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		parts := strings.SplitN(string(record), "\t", 2)
		if len(parts) != 2 || !localExportPath(parts[1]) || want[parts[1]] != "" {
			return ErrDenied
		}
		metadata := strings.Fields(parts[0])
		if len(metadata) != 3 || (metadata[0] != "100644" && metadata[0] != "100755") || metadata[1] != "blob" || !gitObjectPattern.MatchString(metadata[2]) {
			return ErrDenied
		}
		want[parts[1]] = metadata[2]
	}
	if len(want) == 0 || len(want) > 10000 {
		return ErrDenied
	}
	command := exec.CommandContext(ctx, "/usr/bin/git", "--no-pager", "-c", "core.fsmonitor=false", "-C", repository, "archive", "--format=tar", revision)
	command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_NO_REPLACE_OBJECTS=1", "LC_ALL=C"}
	pipe, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		return ErrDenied
	}
	reader := tar.NewReader(io.LimitReader(pipe, 64<<20))
	seen := map[string]bool{}
	valid := true
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			valid = false
			break
		}
		if header.Typeflag == tar.TypeXGlobalHeader && header.Name == "pax_global_header" {
			continue
		}
		if header.Typeflag == tar.TypeDir && localExportPath(strings.TrimSuffix(header.Name, "/")) {
			continue
		}
		if header.Typeflag != tar.TypeReg || !localExportPath(header.Name) || seen[header.Name] || want[header.Name] == "" || header.Size < 0 || header.Size > 8<<20 {
			valid = false
			break
		}
		content, err := io.ReadAll(reader)
		if err != nil || int64(len(content)) != header.Size {
			valid = false
			break
		}
		blob := sha1.New() // Git's existing immutable object identity, not a signature.
		_, _ = fmt.Fprintf(blob, "blob %d\x00", len(content))
		_, _ = blob.Write(content)
		if hex.EncodeToString(blob.Sum(nil)) != want[header.Name] {
			valid = false
			break
		}
		name := filepath.Join(destination, filepath.FromSlash(header.Name))
		if os.MkdirAll(filepath.Dir(name), 0700) != nil {
			valid = false
			break
		}
		file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			valid = false
			break
		}
		_, writeErr := file.Write(content)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			valid = false
			break
		}
		seen[header.Name] = true
	}
	_ = pipe.Close()
	if err := command.Wait(); err != nil || !valid || len(seen) != len(want) {
		return ErrDenied
	}
	return nil
}

func localExportPath(name string) bool {
	return name != "" && name != "." && name == path.Clean(name) && !path.IsAbs(name) && !strings.HasPrefix(name, "../") && name != ".." && !strings.ContainsAny(name, "\\\x00\r\n") && name != ".git" && !strings.HasPrefix(name, ".git/")
}

func localBuildEnvironment(directory, toolchain string) []string {
	return []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=" + directory, "GOROOT=" + toolchain,
		"GOENV=off", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOEXPERIMENT=",
		"GOCACHE=" + filepath.Join(directory, "build-cache"), "GOPATH=" + filepath.Join(directory, "go-path"), "GOMODCACHE=" + filepath.Join(directory, "module-cache"),
		"GOPROXY=" + localModuleProxy, "GOSUMDB=off"}
}

// VerifyLocalDevelopmentExecutable is a nonauthorizing provenance diagnostic
// for the installer composition. It cannot mint an activation or replace the
// compiled-in template/review checks performed by loadLocalTemplate.
func VerifyLocalDevelopmentExecutable(ctx context.Context, repository string) error {
	actual, err := InspectLocalTemplateSource(ctx, repository)
	if err != nil {
		return err
	}
	return verifyLocalExecutable(ctx, repository, actual)
}

// Rebuilding from independently exported tracked bytes closes build flags that
// Go build-info does not record (overlay/modfile/toolexec). No expected executable
// hash is embedded, so source C -> review metadata -> final binary is acyclic.
// This is provenance checking within the trusted local-developer boundary, not
// protection against a same-UID attacker replacing this verifier itself.
func verifyLocalExecutable(ctx context.Context, repository string, core LocalTemplateCore) error {
	directory, err := os.MkdirTemp("", "stead-local-reviewed-build-")
	if err != nil {
		return ErrDenied
	}
	// Retain this private evidence on failure/success; no automatic state cleanup.
	source := filepath.Join(directory, "source")
	if os.Mkdir(source, 0700) != nil || exportLocalSource(ctx, repository, core.SourceRevision, source) != nil {
		return ErrDenied
	}
	toolchain := LocalDevelopmentToolchainDirectory
	// A fresh module cache has no mutable pre-existing unpacked dependencies.
	// Go verifies each fetched build dependency zip against the exact readonly
	// go.sum while unpacking it. Do not fetch unrelated historical test graphs
	// merely to run `go mod verify` over this newly populated compiler cache.
	command := exec.CommandContext(ctx, filepath.Join(toolchain, "bin/go"), "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-pgo=off", "-o", filepath.Join(directory, "stead-api"), "./apps/core")
	command.Dir, command.Env = source, localBuildEnvironment(directory, toolchain)
	var output localGitOutput
	command.Stdout, command.Stderr = &output, &output
	if command.Run() != nil {
		return ErrDenied
	}
	// The module loader is not permitted to change the frozen lock inputs.
	for _, name := range []string{"go.mod", "go.sum"} {
		original, err := os.ReadFile(filepath.Join(repository, name))
		copied, copyErr := os.ReadFile(filepath.Join(source, name))
		if err != nil || copyErr != nil || !bytes.Equal(original, copied) {
			return ErrDenied
		}
	}
	expected, err := localFileDigest(filepath.Join(directory, "stead-api"), 128<<20)
	if err != nil {
		return err
	}
	// Open the actual running executable, not a replaceable argv[0] pathname.
	self, err := os.Open("/proc/self/exe")
	if err != nil {
		return ErrDenied
	}
	defer self.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(self, (128<<20)+1))
	if err != nil || n == 0 || n > 128<<20 || expected != "sha256:"+hex.EncodeToString(hash.Sum(nil)) {
		return ErrDenied
	}
	actual, err := localToolchainDigest(toolchain)
	if err != nil || actual != core.GoToolchainDigest {
		return ErrDenied
	}
	return nil
}
