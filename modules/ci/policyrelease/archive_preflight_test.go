package policyrelease

import (
	"fmt"
	"strings"
	"testing"
)

func divergentArchivePath(prefix string, components int) string {
	parts := make([]string, components)
	for index := range parts {
		parts[index] = fmt.Sprintf("%s%02d", prefix, index)
	}
	return strings.Join(parts, "/")
}

func TestArchiveEntriesRejectDivergentDirectoriesBeforeExcessAccumulation(t *testing.T) {
	files := make([]File, 0, 32)
	for index := 0; index < 31; index++ {
		files = append(files, File{Path: divergentArchivePath(fmt.Sprintf("f%02d-", index), MaxPathComponents)})
	}
	files = append(files, File{Path: divergentArchivePath("last-", MaxPathComponents-1)})
	entries, err := archiveEntries([]byte("envelope"), files)
	if err != nil || len(entries) != MaxArchiveEntries {
		t.Fatalf("exact derived-entry ceiling: entries=%d err=%v (%s)", len(entries), err, ErrorCode(err))
	}

	files[len(files)-1].Path = divergentArchivePath("last-", MaxPathComponents)
	entries, err = archiveEntries([]byte("envelope"), files)
	if ErrorCode(err) != "archive_entry_limit" || entries != nil {
		t.Fatalf("one-over divergent 16-component paths: entries=%d err=%v (%s)", len(entries), err, ErrorCode(err))
	}
}
