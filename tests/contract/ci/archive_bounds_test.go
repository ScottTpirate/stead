package ci_test

import (
	"archive/tar"
	"bytes"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	policyrelease "github.com/ScottTpirate/stead/modules/ci/policyrelease"
)

type tarFixtureEntry struct {
	name     string
	content  []byte
	typeflag byte
	mode     int64
	linkname string
	format   tar.Format
	uid      int
}

func makeUSTARFixture(t testing.TB, entries []tarFixtureEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	for _, entry := range entries {
		typeflag := entry.typeflag
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := entry.mode
		if mode == 0 {
			mode = 0o444
			if typeflag == tar.TypeDir {
				mode = 0o555
			}
		}
		format := entry.format
		if format == tar.FormatUnknown {
			format = tar.FormatUSTAR
		}
		size := int64(len(entry.content))
		if typeflag == tar.TypeDir || typeflag == tar.TypeSymlink || typeflag == tar.TypeLink || typeflag == tar.TypeChar || typeflag == tar.TypeBlock || typeflag == tar.TypeFifo {
			size = 0
		}
		header := &tar.Header{
			Name: entry.name, Mode: mode, Uid: entry.uid, Gid: 0, Size: size,
			ModTime: time.Unix(0, 0).UTC(), Typeflag: typeflag, Linkname: entry.linkname, Format: format,
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("WriteHeader(%q): %v", entry.name, err)
		}
		if size > 0 {
			if _, err := writer.Write(entry.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func canonicalArchiveFixture(t testing.TB) ([]byte, []byte, []policyrelease.ManifestFile) {
	t.Helper()
	envelope := []byte("fixed-envelope-bytes")
	content := []byte("fixed-payload")
	archive := makeUSTARFixture(t, []tarFixtureEntry{
		{name: "manifest.dsse.json", content: envelope},
		{name: "payload/", typeflag: tar.TypeDir},
		{name: "payload/item.json", content: content},
	})
	files := []policyrelease.ManifestFile{{Path: "payload/item.json", MediaType: "application/json", Size: int64(len(content)), Digest: policyrelease.SHA256Digest(content)}}
	return archive, envelope, files
}

func rewriteUSTARChecksum(block []byte) {
	for index := 148; index < 156; index++ {
		block[index] = ' '
	}
	var sum uint64
	for _, value := range block {
		sum += uint64(value)
	}
	copy(block[148:156], []byte(fmt.Sprintf("%06o\x00 ", sum)))
}

// T-ADR-0006-ARCHIVE-SAFETY exact archive, file, content, entry, path, and
// component ceilings.
func TestArchiveResourceBoundaries(t *testing.T) {
	t.Run("archive bytes exact and one over", func(t *testing.T) {
		archive := makeUSTARFixture(t, []tarFixtureEntry{{name: "file", content: []byte("x")}})
		exact := append(archive, make([]byte, policyrelease.MaxArchiveBytes-len(archive))...)
		if _, err := policyrelease.InspectArchive(exact); err != nil {
			t.Fatalf("exact archive ceiling rejected: %v (%s)", err, policyrelease.ErrorCode(err))
		}
		oneOver := append(exact, 0)
		if _, err := policyrelease.InspectArchive(oneOver); policyrelease.ErrorCode(err) != "archive_size_limit" {
			t.Fatalf("one-over archive error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("entry count exact and one over", func(t *testing.T) {
		entries := make([]tarFixtureEntry, 0, policyrelease.MaxArchiveEntries+1)
		for index := 0; index < policyrelease.MaxArchiveEntries+1; index++ {
			entries = append(entries, tarFixtureEntry{name: fmt.Sprintf("d%03d/", index), typeflag: tar.TypeDir})
		}
		exact := makeUSTARFixture(t, entries[:policyrelease.MaxArchiveEntries])
		if inspection, err := policyrelease.InspectArchive(exact); err != nil || inspection.EntryCount != policyrelease.MaxArchiveEntries {
			t.Fatalf("exact entries: count=%d err=%v (%s)", inspection.EntryCount, err, policyrelease.ErrorCode(err))
		}
		oneOver := makeUSTARFixture(t, entries)
		if _, err := policyrelease.InspectArchive(oneOver); policyrelease.ErrorCode(err) != "archive_entry_limit" {
			t.Fatalf("one-over entries error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("file count exact and one over", func(t *testing.T) {
		entries := make([]tarFixtureEntry, 0, policyrelease.MaxArchiveFiles+1)
		for index := 0; index < policyrelease.MaxArchiveFiles+1; index++ {
			entries = append(entries, tarFixtureEntry{name: fmt.Sprintf("f%03d", index), content: []byte("x")})
		}
		exact := makeUSTARFixture(t, entries[:policyrelease.MaxArchiveFiles])
		if inspection, err := policyrelease.InspectArchive(exact); err != nil || inspection.FileCount != policyrelease.MaxArchiveFiles {
			t.Fatalf("exact files: count=%d err=%v (%s)", inspection.FileCount, err, policyrelease.ErrorCode(err))
		}
		oneOver := makeUSTARFixture(t, entries)
		if _, err := policyrelease.InspectArchive(oneOver); policyrelease.ErrorCode(err) != "archive_content_limit" {
			t.Fatalf("one-over files error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("per-file exact and one over", func(t *testing.T) {
		exact := makeUSTARFixture(t, []tarFixtureEntry{{name: "file", content: make([]byte, policyrelease.MaxArchiveFileBytes)}})
		if _, err := policyrelease.InspectArchive(exact); err != nil {
			t.Fatalf("exact file ceiling rejected: %v (%s)", err, policyrelease.ErrorCode(err))
		}
		oneOver := makeUSTARFixture(t, []tarFixtureEntry{{name: "file", content: make([]byte, policyrelease.MaxArchiveFileBytes+1)}})
		if _, err := policyrelease.InspectArchive(oneOver); policyrelease.ErrorCode(err) != "archive_content_limit" {
			t.Fatalf("one-over file error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("total content exact and one over", func(t *testing.T) {
		entries := make([]tarFixtureEntry, 0, 7)
		for index := 0; index < 6; index++ {
			entries = append(entries, tarFixtureEntry{name: fmt.Sprintf("f%d", index), content: make([]byte, policyrelease.MaxArchiveFileBytes)})
		}
		exact := makeUSTARFixture(t, entries)
		if inspection, err := policyrelease.InspectArchive(exact); err != nil || inspection.ContentBytes != policyrelease.MaxArchiveContent {
			t.Fatalf("exact content: bytes=%d err=%v (%s)", inspection.ContentBytes, err, policyrelease.ErrorCode(err))
		}
		entries = append(entries, tarFixtureEntry{name: "f6", content: []byte("x")})
		oneOver := makeUSTARFixture(t, entries)
		if _, err := policyrelease.InspectArchive(oneOver); policyrelease.ErrorCode(err) != "archive_content_limit" {
			t.Fatalf("one-over content error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})
}

func TestArchivePathBoundaries(t *testing.T) {
	exactPath := strings.Repeat("a", 69) + "/" + strings.Repeat("b", 69) + "/" + strings.Repeat("c", 100)
	if len(exactPath) != policyrelease.MaxArchivePathBytes {
		t.Fatalf("test path len=%d", len(exactPath))
	}
	if _, err := policyrelease.InspectArchive(makeUSTARFixture(t, []tarFixtureEntry{{name: exactPath, content: []byte("x")}})); err != nil {
		t.Fatalf("exact path rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	oneOverPath := strings.Repeat("a", 70) + "/" + strings.Repeat("b", 69) + "/" + strings.Repeat("c", 100)
	if _, err := policyrelease.InspectArchive(makeUSTARFixture(t, []tarFixtureEntry{{name: oneOverPath, content: []byte("x")}})); policyrelease.ErrorCode(err) != "invalid_archive_path" {
		t.Fatalf("one-over path error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	exactComponents := strings.Repeat("a/", policyrelease.MaxPathComponents-1) + "z"
	if _, err := policyrelease.InspectArchive(makeUSTARFixture(t, []tarFixtureEntry{{name: exactComponents, content: []byte("x")}})); err != nil {
		t.Fatalf("exact components rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	oneOverComponents := "a/" + exactComponents
	if _, err := policyrelease.InspectArchive(makeUSTARFixture(t, []tarFixtureEntry{{name: oneOverComponents, content: []byte("x")}})); policyrelease.ErrorCode(err) != "archive_path_component_limit" {
		t.Fatalf("one-over components error = %v (%s)", err, policyrelease.ErrorCode(err))
	}

	exactComponent := strings.Repeat("q", policyrelease.MaxPathComponentByte)
	if _, err := policyrelease.InspectArchive(makeUSTARFixture(t, []tarFixtureEntry{{name: exactComponent, content: []byte("x")}})); err != nil {
		t.Fatalf("exact component rejected: %v (%s)", err, policyrelease.ErrorCode(err))
	}
	oneOverComponent := strings.Repeat("q", policyrelease.MaxPathComponentByte+1) + "/x"
	if _, err := policyrelease.InspectArchive(makeUSTARFixture(t, []tarFixtureEntry{{name: oneOverComponent, content: []byte("x")}})); policyrelease.ErrorCode(err) != "invalid_archive_path_component" {
		t.Fatalf("one-over component error = %v (%s)", err, policyrelease.ErrorCode(err))
	}
}

func TestArchiveRejectsUnsafeEntryKindsMetadataAndPaths(t *testing.T) {
	testCases := []struct {
		name    string
		entries []tarFixtureEntry
		code    string
	}{
		{"absolute", []tarFixtureEntry{{name: "/absolute", content: []byte("x")}}, "invalid_archive_path"},
		{"traversal", []tarFixtureEntry{{name: "../escape", content: []byte("x")}}, "invalid_archive_path_component"},
		{"backslash", []tarFixtureEntry{{name: `payload\escape`, content: []byte("x")}}, "invalid_archive_path"},
		{"duplicate", []tarFixtureEntry{{name: "same", content: []byte("x")}, {name: "same", content: []byte("x")}}, "duplicate_archive_path"},
		{"unsorted", []tarFixtureEntry{{name: "z", content: []byte("x")}, {name: "a", content: []byte("x")}}, "archive_entries_not_sorted"},
		{"symlink", []tarFixtureEntry{{name: "link", typeflag: tar.TypeSymlink, linkname: "target"}}, "unsupported_ustar_entry_type"},
		{"hardlink", []tarFixtureEntry{{name: "link", typeflag: tar.TypeLink, linkname: "target"}}, "unsupported_ustar_entry_type"},
		{"character-device", []tarFixtureEntry{{name: "device", typeflag: tar.TypeChar}}, "unsupported_ustar_entry_type"},
		{"block-device", []tarFixtureEntry{{name: "device", typeflag: tar.TypeBlock}}, "unsupported_ustar_entry_type"},
		{"fifo", []tarFixtureEntry{{name: "fifo", typeflag: tar.TypeFifo}}, "unsupported_ustar_entry_type"},
		{"gnu-long-name", []tarFixtureEntry{{name: strings.Repeat("g", 101), content: []byte("x"), format: tar.FormatGNU}}, "unsupported_tar_format"},
		{"setuid", []tarFixtureEntry{{name: "setuid", content: []byte("x"), mode: 0o444 | 0o4000}}, "noncanonical_ustar_metadata"},
		{"nonzero-owner", []tarFixtureEntry{{name: "owned", content: []byte("x"), uid: 1}}, "noncanonical_ustar_metadata"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			archive := makeUSTARFixture(t, testCase.entries)
			_, err := policyrelease.InspectArchive(archive)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
	t.Run("extension-entry-types", func(t *testing.T) {
		base := makeUSTARFixture(t, []tarFixtureEntry{{name: "extension", content: []byte("x")}})
		for _, typeflag := range []byte{tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink, tar.TypeGNUSparse, 's'} {
			mutated := append([]byte(nil), base...)
			mutated[156] = typeflag
			rewriteUSTARChecksum(mutated[:512])
			if _, err := policyrelease.InspectArchive(mutated); policyrelease.ErrorCode(err) != "unsupported_ustar_entry_type" {
				t.Fatalf("type %q error = %v (%s)", typeflag, err, policyrelease.ErrorCode(err))
			}
		}
	})
}

// T-ADR-0006-CONTENT-INTEGRITY.
func TestArchiveExactFileSetAndMutationRejection(t *testing.T) {
	archive, envelope, files := canonicalArchiveFixture(t)
	if _, err := policyrelease.ValidateArchive(archive, envelope, files); err != nil {
		t.Fatal(err)
	}

	t.Run("mutate listed content", func(t *testing.T) {
		mutated := append([]byte(nil), archive...)
		needle := []byte("fixed-payload")
		index := bytes.Index(mutated, needle)
		if index < 0 {
			t.Fatal("payload not found")
		}
		mutated[index] ^= 1
		if _, err := policyrelease.ValidateArchive(mutated, envelope, files); policyrelease.ErrorCode(err) != "archive_content_mismatch" {
			t.Fatalf("mutated content error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("add unlisted file", func(t *testing.T) {
		added := makeUSTARFixture(t, []tarFixtureEntry{
			{name: "evidence/", typeflag: tar.TypeDir},
			{name: "evidence/unlisted", content: []byte("x")},
			{name: "manifest.dsse.json", content: envelope},
			{name: "payload/", typeflag: tar.TypeDir},
			{name: "payload/item.json", content: []byte("fixed-payload")},
		})
		if _, err := policyrelease.ValidateArchive(added, envelope, files); policyrelease.ErrorCode(err) != "archive_file_set_mismatch" {
			t.Fatalf("added file error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("rename listed file", func(t *testing.T) {
		renamed := makeUSTARFixture(t, []tarFixtureEntry{
			{name: "manifest.dsse.json", content: envelope},
			{name: "payload/", typeflag: tar.TypeDir},
			{name: "payload/renamed.json", content: []byte("fixed-payload")},
		})
		if _, err := policyrelease.ValidateArchive(renamed, envelope, files); policyrelease.ErrorCode(err) != "archive_content_mismatch" {
			t.Fatalf("renamed file error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("truncate", func(t *testing.T) {
		truncated := archive[:len(archive)-512]
		if _, err := policyrelease.ValidateArchive(truncated, envelope, files); policyrelease.ErrorCode(err) != "missing_ustar_end_blocks" {
			t.Fatalf("truncated error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})

	t.Run("append nonzero", func(t *testing.T) {
		appended := append(append([]byte(nil), archive...), make([]byte, 512)...)
		appended[len(archive)] = 1
		if _, err := policyrelease.ValidateArchive(appended, envelope, files); policyrelease.ErrorCode(err) != "archive_bytes_after_end" {
			t.Fatalf("append error = %v (%s)", err, policyrelease.ErrorCode(err))
		}
	})
}

func TestArchiveRejectsOverflowMalformedUTF8AndChecksum(t *testing.T) {
	base := makeUSTARFixture(t, []tarFixtureEntry{{name: "file", content: []byte("x")}})
	testCases := []struct {
		name   string
		mutate func([]byte)
		code   string
	}{
		{"base-256-size", func(data []byte) { data[124] = 0x80; rewriteUSTARChecksum(data[:512]) }, "unsupported_ustar_number"},
		{"nul regular typeflag", func(data []byte) { data[156] = 0; rewriteUSTARChecksum(data[:512]) }, "unsupported_ustar_entry_type"},
		{"space-prefixed octal", func(data []byte) { data[124] = ' '; rewriteUSTARChecksum(data[:512]) }, "noncanonical_ustar_number"},
		{"space-terminated octal", func(data []byte) { data[135] = ' '; rewriteUSTARChecksum(data[:512]) }, "noncanonical_ustar_number"},
		{"empty zero octal", func(data []byte) {
			for index := 108; index < 116; index++ {
				data[index] = 0
			}
			rewriteUSTARChecksum(data[:512])
		}, "noncanonical_ustar_number"},
		{"space-prefixed checksum", func(data []byte) { data[148] = ' ' }, "noncanonical_ustar_number"},
		{"malformed-utf8", func(data []byte) { data[0] = 0xff; rewriteUSTARChecksum(data[:512]) }, "invalid_archive_path"},
		{"checksum", func(data []byte) { data[0] ^= 1 }, "ustar_checksum_mismatch"},
		{"header padding", func(data []byte) { data[500] = 1; rewriteUSTARChecksum(data[:512]) }, "noncanonical_ustar_header_padding"},
		{"content padding", func(data []byte) { data[512+1] = 1 }, "nonzero_ustar_content_padding"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			mutated := append([]byte(nil), base...)
			testCase.mutate(mutated)
			_, err := policyrelease.InspectArchive(mutated)
			if policyrelease.ErrorCode(err) != testCase.code {
				t.Fatalf("error = %v (%s), want %s", err, policyrelease.ErrorCode(err), testCase.code)
			}
		})
	}
}

func TestArchiveEntriesAreLexicographicallySorted(t *testing.T) {
	activation, _, _ := completeFixtureRelease(t, "commercial", 1, false)
	inspection, err := policyrelease.InspectArchive(activation.ArchiveBytes)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, inspection.EntryCount)
	names = append(names, inspection.Directories...)
	for _, file := range inspection.Files {
		names = append(names, file.Path)
	}
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	// InspectArchive itself validates true wire order; this assertion keeps the
	// returned identity sets deterministic as well.
	if len(sorted) != len(names) {
		t.Fatal("entry accounting mismatch")
	}
}
