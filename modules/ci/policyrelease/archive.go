package policyrelease

import (
	"archive/tar"
	"bytes"
	"sort"
	"strings"
	"time"
)

type archiveEntry struct {
	name      string
	directory bool
	content   []byte
}

type ArchiveInspection struct {
	ArchiveDigest string
	EntryCount    int
	FileCount     int
	ContentBytes  uint64
	Files         []ManifestFile
	Directories   []string
}

const ustarBlockSize = 512

func archiveEntries(envelope []byte, files []File) []archiveEntry {
	entries := []archiveEntry{{name: "manifest.dsse.json", content: envelope}}
	directories := make(map[string]struct{})
	for _, file := range files {
		parts := strings.Split(file.Path, "/")
		for i := 1; i < len(parts); i++ {
			directories[strings.Join(parts[:i], "/")+"/"] = struct{}{}
		}
		entries = append(entries, archiveEntry{name: file.Path, content: file.Content})
	}
	for directory := range directories {
		entries = append(entries, archiveEntry{name: directory, directory: true})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	return entries
}

func writeArchive(envelope []byte, files []File) ([]byte, error) {
	if len(files) >= MaxArchiveFiles || len(envelope) > MaxArchiveFileBytes {
		return nil, contractError("archive_content_limit", "files", nil)
	}
	totalContent := uint64(len(envelope))
	for _, file := range files {
		if len(file.Content) > MaxArchiveFileBytes || totalContent > MaxArchiveContent-uint64(len(file.Content)) {
			return nil, contractError("archive_content_limit", file.Path, nil)
		}
		totalContent += uint64(len(file.Content))
	}
	entries := archiveEntries(envelope, files)
	if len(entries) > MaxArchiveEntries {
		return nil, contractError("archive_entry_limit", "archive", nil)
	}
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     0o444,
			Uid:      0,
			Gid:      0,
			Size:     int64(len(entry.content)),
			ModTime:  time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}
		if entry.directory {
			header.Mode = 0o555
			header.Size = 0
			header.Typeflag = tar.TypeDir
		}
		if err := writer.WriteHeader(header); err != nil {
			return nil, contractError("ustar_header_write_failed", entry.name, err)
		}
		if !entry.directory {
			if _, err := writer.Write(entry.content); err != nil {
				return nil, contractError("ustar_content_write_failed", entry.name, err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		return nil, contractError("ustar_close_failed", "archive", err)
	}
	if buffer.Len() > MaxArchiveBytes {
		return nil, contractError("archive_size_limit", "archive", nil)
	}
	return buffer.Bytes(), nil
}

func parseUSTARString(field []byte) (string, error) {
	end := bytes.IndexByte(field, 0)
	if end < 0 {
		end = len(field)
	} else if !allZero(field[end:]) {
		return "", contractError("noncanonical_ustar_string", "archive", nil)
	}
	return string(field[:end]), nil
}

func parseUSTAROctal(field []byte) (uint64, error) {
	if len(field) == 0 || field[0]&0x80 != 0 {
		return 0, contractError("unsupported_ustar_number", "archive", nil)
	}
	start := 0
	for start < len(field) && field[start] == ' ' {
		start++
	}
	end := start
	for end < len(field) && field[end] >= '0' && field[end] <= '7' {
		end++
	}
	if end == start {
		for _, value := range field {
			if value != 0 && value != ' ' {
				return 0, contractError("malformed_ustar_number", "archive", nil)
			}
		}
		return 0, nil
	}
	for _, value := range field[end:] {
		if value != 0 && value != ' ' {
			return 0, contractError("malformed_ustar_number", "archive", nil)
		}
	}
	var result uint64
	for _, value := range field[start:end] {
		if result > (^uint64(0)-uint64(value-'0'))/8 {
			return 0, contractError("ustar_number_overflow", "archive", nil)
		}
		result = result*8 + uint64(value-'0')
	}
	return result, nil
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func verifyUSTARChecksum(block []byte) error {
	want, err := parseUSTAROctal(block[148:156])
	if err != nil {
		return err
	}
	var got uint64
	for i, value := range block {
		if i >= 148 && i < 156 {
			got += uint64(' ')
		} else {
			got += uint64(value)
		}
	}
	if got != want {
		return contractError("ustar_checksum_mismatch", "archive", nil)
	}
	return nil
}

func expectedDirectories(files []ManifestFile) []string {
	set := make(map[string]struct{})
	for _, file := range files {
		parts := strings.Split(file.Path, "/")
		for i := 1; i < len(parts); i++ {
			set[strings.Join(parts[:i], "/")+"/"] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for directory := range set {
		result = append(result, directory)
	}
	sort.Strings(result)
	return result
}

// InspectArchive validates the strict bounded ustar framing before returning
// content identities. It never extracts paths to disk.
func InspectArchive(archive []byte) (ArchiveInspection, error) {
	if len(archive) == 0 || len(archive) > MaxArchiveBytes || len(archive)%ustarBlockSize != 0 {
		return ArchiveInspection{}, contractError("archive_size_limit", "archive", nil)
	}
	inspection := ArchiveInspection{ArchiveDigest: SHA256Digest(archive)}
	seen := make(map[string]struct{})
	offset := uint64(0)
	zeroBlocks := 0
	for offset+ustarBlockSize <= uint64(len(archive)) {
		block := archive[offset : offset+ustarBlockSize]
		if allZero(block) {
			zeroBlocks++
			offset += ustarBlockSize
			if zeroBlocks >= 2 {
				if !allZero(archive[offset:]) {
					return ArchiveInspection{}, contractError("archive_bytes_after_end", "archive", nil)
				}
				offset = uint64(len(archive))
				break
			}
			continue
		}
		if zeroBlocks != 0 {
			return ArchiveInspection{}, contractError("single_zero_ustar_block", "archive", nil)
		}
		if inspection.EntryCount >= MaxArchiveEntries {
			return ArchiveInspection{}, contractError("archive_entry_limit", "archive", nil)
		}
		if err := verifyUSTARChecksum(block); err != nil {
			return ArchiveInspection{}, err
		}
		if !bytes.Equal(block[257:263], []byte{'u', 's', 't', 'a', 'r', 0}) || !bytes.Equal(block[263:265], []byte{'0', '0'}) {
			return ArchiveInspection{}, contractError("unsupported_tar_format", "archive", nil)
		}
		if !allZero(block[500:512]) {
			return ArchiveInspection{}, contractError("noncanonical_ustar_header_padding", "archive", nil)
		}
		name, err := parseUSTARString(block[0:100])
		if err != nil {
			return ArchiveInspection{}, err
		}
		prefix, err := parseUSTARString(block[345:500])
		if err != nil {
			return ArchiveInspection{}, err
		}
		if prefix != "" {
			name = prefix + "/" + name
		}
		typeflag := block[156]
		directory := typeflag == tar.TypeDir
		if typeflag != tar.TypeReg && typeflag != 0 && !directory {
			return ArchiveInspection{}, contractError("unsupported_ustar_entry_type", name, nil)
		}
		if err := validatePath(name, directory); err != nil {
			return ArchiveInspection{}, err
		}
		if _, duplicate := seen[name]; duplicate {
			return ArchiveInspection{}, contractError("duplicate_archive_path", name, nil)
		}
		seen[name] = struct{}{}
		if inspection.EntryCount > 0 {
			previous := ""
			if len(inspection.Files) > 0 || len(inspection.Directories) > 0 {
				// Track lexical order independently of entry kind.
				previous = archiveEntryNameAt(inspection)
			}
			if previous != "" && name <= previous {
				return ArchiveInspection{}, contractError("archive_entries_not_sorted", name, nil)
			}
		}
		mode, err := parseUSTAROctal(block[100:108])
		if err != nil {
			return ArchiveInspection{}, err
		}
		uid, err := parseUSTAROctal(block[108:116])
		if err != nil {
			return ArchiveInspection{}, err
		}
		gid, err := parseUSTAROctal(block[116:124])
		if err != nil {
			return ArchiveInspection{}, err
		}
		size, err := parseUSTAROctal(block[124:136])
		if err != nil {
			return ArchiveInspection{}, err
		}
		mtime, err := parseUSTAROctal(block[136:148])
		if err != nil {
			return ArchiveInspection{}, err
		}
		linkName, err := parseUSTARString(block[157:257])
		if err != nil {
			return ArchiveInspection{}, err
		}
		userName, err := parseUSTARString(block[265:297])
		if err != nil {
			return ArchiveInspection{}, err
		}
		groupName, err := parseUSTARString(block[297:329])
		if err != nil {
			return ArchiveInspection{}, err
		}
		devMajor, err := parseUSTAROctal(block[329:337])
		if err != nil {
			return ArchiveInspection{}, err
		}
		devMinor, err := parseUSTAROctal(block[337:345])
		if err != nil {
			return ArchiveInspection{}, err
		}
		expectedMode := uint64(0o444)
		if directory {
			expectedMode = 0o555
		}
		if mode != expectedMode || uid != 0 || gid != 0 || mtime != 0 || linkName != "" || userName != "" || groupName != "" || devMajor != 0 || devMinor != 0 {
			return ArchiveInspection{}, contractError("noncanonical_ustar_metadata", name, nil)
		}
		if directory && size != 0 {
			return ArchiveInspection{}, contractError("directory_with_content", name, nil)
		}
		if !directory {
			if inspection.FileCount >= MaxArchiveFiles || size > MaxArchiveFileBytes || inspection.ContentBytes > MaxArchiveContent-size {
				return ArchiveInspection{}, contractError("archive_content_limit", name, nil)
			}
			contentStart := offset + ustarBlockSize
			contentEnd := contentStart + size
			if contentEnd < contentStart || contentEnd > uint64(len(archive)) {
				return ArchiveInspection{}, contractError("truncated_ustar_content", name, nil)
			}
			content := archive[contentStart:contentEnd]
			paddedEnd := contentStart + ((size + ustarBlockSize - 1) / ustarBlockSize * ustarBlockSize)
			if paddedEnd < contentEnd || paddedEnd > uint64(len(archive)) || !allZero(archive[contentEnd:paddedEnd]) {
				return ArchiveInspection{}, contractError("nonzero_ustar_content_padding", name, nil)
			}
			inspection.Files = append(inspection.Files, ManifestFile{Path: name, Size: int64(size), Digest: SHA256Digest(content)})
			inspection.FileCount++
			inspection.ContentBytes += size
		} else {
			inspection.Directories = append(inspection.Directories, name)
		}
		inspection.EntryCount++
		blocks := (size + ustarBlockSize - 1) / ustarBlockSize
		advance := uint64(ustarBlockSize) + blocks*ustarBlockSize
		if advance < uint64(ustarBlockSize) || offset > uint64(len(archive)) || advance > uint64(len(archive))-offset {
			return ArchiveInspection{}, contractError("ustar_size_overflow", name, nil)
		}
		offset += advance
	}
	if zeroBlocks < 2 || offset != uint64(len(archive)) {
		return ArchiveInspection{}, contractError("missing_ustar_end_blocks", "archive", nil)
	}
	return inspection, nil
}

func archiveEntryNameAt(inspection ArchiveInspection) string {
	lastFile := ""
	if len(inspection.Files) > 0 {
		lastFile = inspection.Files[len(inspection.Files)-1].Path
	}
	lastDirectory := ""
	if len(inspection.Directories) > 0 {
		lastDirectory = inspection.Directories[len(inspection.Directories)-1]
	}
	if lastDirectory > lastFile {
		return lastDirectory
	}
	return lastFile
}

// ValidateArchive verifies that the archive contains exactly one supplied DSSE
// envelope and each digest-listed payload/evidence file, with no other entry.
func ValidateArchive(archive, envelope []byte, files []ManifestFile) (ArchiveInspection, error) {
	inspection, err := InspectArchive(archive)
	if err != nil {
		return ArchiveInspection{}, err
	}
	expectedFiles := make(map[string]ManifestFile, len(files)+1)
	expectedFiles["manifest.dsse.json"] = ManifestFile{Path: "manifest.dsse.json", Size: int64(len(envelope)), Digest: SHA256Digest(envelope)}
	for _, file := range files {
		if file.Path == "manifest.dsse.json" || (!strings.HasPrefix(file.Path, "payload/") && !strings.HasPrefix(file.Path, "evidence/")) {
			return ArchiveInspection{}, contractError("invalid_manifest_file_path", file.Path, nil)
		}
		if _, duplicate := expectedFiles[file.Path]; duplicate {
			return ArchiveInspection{}, contractError("duplicate_manifest_file", file.Path, nil)
		}
		expectedFiles[file.Path] = file
	}
	if len(inspection.Files) != len(expectedFiles) {
		return ArchiveInspection{}, contractError("archive_file_set_mismatch", "archive", nil)
	}
	for _, actual := range inspection.Files {
		expected, ok := expectedFiles[actual.Path]
		if !ok || actual.Size != expected.Size || actual.Digest != expected.Digest {
			return ArchiveInspection{}, contractError("archive_content_mismatch", actual.Path, nil)
		}
	}
	wantDirectories := expectedDirectories(files)
	if len(wantDirectories) != len(inspection.Directories) {
		return ArchiveInspection{}, contractError("archive_directory_set_mismatch", "archive", nil)
	}
	for i := range wantDirectories {
		if wantDirectories[i] != inspection.Directories[i] {
			return ArchiveInspection{}, contractError("archive_directory_set_mismatch", inspection.Directories[i], nil)
		}
	}
	return inspection, nil
}

func manifestFileList(files []File) []ManifestFile {
	result := make([]ManifestFile, 0, len(files))
	for _, file := range files {
		result = append(result, ManifestFile{Path: file.Path, MediaType: file.MediaType, Size: int64(len(file.Content)), Digest: SHA256Digest(file.Content)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}

// FinalizeActivationArchive accepts externally signed bytes and constructs the
// deterministic archive for that exact envelope.
func FinalizeActivationArchive(unsigned UnsignedActivation, envelope []byte, signing SigningResult) (ActivationArchive, error) {
	if err := validateUnsignedActivation(unsigned); err != nil {
		return ActivationArchive{}, err
	}
	parsed, err := validateExpectedEnvelope(envelope, unsigned.ManifestPayload, ActivationManifestPayloadType)
	if err != nil {
		return ActivationArchive{}, err
	}
	threshold, err := validateSigningResult(parsed, signing, unsigned.Manifest.DeploymentPolicy)
	if err != nil {
		return ActivationArchive{}, err
	}
	if signing.WorkflowIdentity == unsigned.EvidenceManifest.BuilderIdentity || signing.WorkflowIdentity == unsigned.EvidenceManifest.BuildWorkflowIdentity {
		return ActivationArchive{}, contractError("builder_signing_workflow_not_separated", "signing_result.workflow_identity", nil)
	}
	archive, err := writeArchive(envelope, unsigned.Files)
	if err != nil {
		return ActivationArchive{}, err
	}
	if _, err := ValidateArchive(archive, envelope, unsigned.Manifest.Files); err != nil {
		return ActivationArchive{}, err
	}
	return ActivationArchive{
		Unsigned:             unsigned,
		EnvelopeBytes:        append([]byte(nil), envelope...),
		SignedEnvelopeDigest: SHA256Digest(envelope),
		ArchiveBytes:         append([]byte(nil), archive...),
		ArchiveDigest:        SHA256Digest(archive),
		ActivationSigning:    copySigningResult(signing),
		Threshold:            threshold,
	}, nil
}
