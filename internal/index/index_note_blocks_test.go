package index

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndexNoteStoresBlocksAndDirectTags(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	content := strings.Join([]string{
		"# demo",
		"",
		"this is demo",
		"",
		"- data",
		"  xx",
		"  - sub-data",
		"    this is yyy #tag1",
		"",
		"  #tag2",
	}, "\n")
	noteName := "demo.md"
	fullPath := filepath.Join(notesDir, noteName)
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write note: %v", err)
	}

	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()

	ctx := context.Background()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	var fileID int
	if err := idx.queryRowContext(ctx, `
		SELECT files.id
		FROM files
		JOIN users ON users.id = files.user_id
		WHERE users.name = ? AND files.path = ?
	`, owner, noteName).Scan(&fileID); err != nil {
		t.Fatalf("resolve file id: %v", err)
	}

	blocks := ParseNoteBlocks(content)
	if len(blocks) == 0 {
		t.Fatalf("expected parsed blocks")
	}
	var dataBlockID int
	var subDataBlockID int
	for _, block := range blocks {
		if block.StartLine == 5 {
			dataBlockID = block.ID
		}
		if block.StartLine == 7 {
			subDataBlockID = block.ID
		}
	}
	if dataBlockID == 0 || subDataBlockID == 0 {
		t.Fatalf("failed to resolve data/sub-data block ids from %+v", blocks)
	}

	var persistedCount int
	if err := idx.queryRowContext(ctx, "SELECT COUNT(*) FROM note_blocks WHERE file_id = ?", fileID).Scan(&persistedCount); err != nil {
		t.Fatalf("count note_blocks: %v", err)
	}
	if persistedCount != len(blocks) {
		t.Fatalf("unexpected block count: got %d want %d", persistedCount, len(blocks))
	}

	tagsByBlock := map[int][]string{}
	rows, err := idx.queryContext(ctx, "SELECT block_id, tag FROM note_block_tags WHERE file_id = ?", fileID)
	if err != nil {
		t.Fatalf("load note_block_tags: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var blockID int
		var tag string
		if err := rows.Scan(&blockID, &tag); err != nil {
			t.Fatalf("scan note_block_tags: %v", err)
		}
		tagsByBlock[blockID] = append(tagsByBlock[blockID], tag)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate note_block_tags: %v", err)
	}

	if !containsTag(tagsByBlock[dataBlockID], "tag2") {
		t.Fatalf("expected #tag2 on data block, got %+v", tagsByBlock)
	}
	if containsTag(tagsByBlock[dataBlockID], "tag1") {
		t.Fatalf("did not expect #tag1 on data block, got %+v", tagsByBlock[dataBlockID])
	}
	if !containsTag(tagsByBlock[subDataBlockID], "tag1") {
		t.Fatalf("expected #tag1 on sub-data block, got %+v", tagsByBlock)
	}
	if containsTag(tagsByBlock[subDataBlockID], "tag2") {
		t.Fatalf("did not expect #tag2 on sub-data block, got %+v", tagsByBlock[subDataBlockID])
	}

	tagOwners := map[string][]int{}
	for blockID, tags := range tagsByBlock {
		for _, tag := range tags {
			tagOwners[tag] = append(tagOwners[tag], blockID)
		}
	}
	if len(tagOwners["tag1"]) != 1 || tagOwners["tag1"][0] != subDataBlockID {
		t.Fatalf("expected #tag1 only on sub-data block %d, got %+v", subDataBlockID, tagOwners["tag1"])
	}
	if len(tagOwners["tag2"]) != 1 || tagOwners["tag2"][0] != dataBlockID {
		t.Fatalf("expected #tag2 only on data block %d, got %+v", dataBlockID, tagOwners["tag2"])
	}
}

func TestNoteBlocksSchemaHasNoContentColumn(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	if err := os.MkdirAll(filepath.Join(repo, owner, "notes"), 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()
	if err := idx.Init(context.Background(), repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	columns := map[string]struct{}{}
	rows, err := idx.queryContext(context.Background(), "PRAGMA table_info(note_blocks)")
	if err != nil {
		t.Fatalf("table info note_blocks: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid      int
			name     string
			colType  string
			notNull  int
			defaultV sql.NullString
			primaryK int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &primaryK); err != nil {
			t.Fatalf("scan table info: %v", err)
		}
		columns[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate table info: %v", err)
	}

	for _, required := range []string{"file_id", "block_id", "parent_block_id", "level", "start_line", "end_line"} {
		if _, ok := columns[required]; !ok {
			t.Fatalf("expected note_blocks column %q, got %+v", required, columns)
		}
	}
	for _, forbidden := range []string{"content", "content_md", "markdown"} {
		if _, ok := columns[forbidden]; ok {
			t.Fatalf("unexpected note_blocks content column %q", forbidden)
		}
	}
}

func TestFindNoteBlocksByTagRespectsVisibility(t *testing.T) {
	repo := t.TempDir()
	owner := "local"
	notesDir := filepath.Join(repo, owner, "notes")
	if err := os.MkdirAll(notesDir, 0o755); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	dataDir := filepath.Join(repo, ".wiki")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir .wiki: %v", err)
	}

	publicNote := strings.Join([]string{
		"---",
		"visibility: public",
		"---",
		"# public",
		"",
		"line #demo",
	}, "\n")
	privateNote := strings.Join([]string{
		"---",
		"visibility: private",
		"---",
		"# private",
		"",
		"line #demo",
	}, "\n")
	if err := os.WriteFile(filepath.Join(notesDir, "public.md"), []byte(publicNote), 0o644); err != nil {
		t.Fatalf("write public note: %v", err)
	}
	if err := os.WriteFile(filepath.Join(notesDir, "private.md"), []byte(privateNote), 0o644); err != nil {
		t.Fatalf("write private note: %v", err)
	}

	idx, err := Open(filepath.Join(dataDir, "index.sqlite"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	defer idx.Close()
	ctx := context.Background()
	if err := idx.Init(ctx, repo); err != nil {
		t.Fatalf("init index: %v", err)
	}

	allMatches, err := idx.FindNoteBlocksByTag(ctx, "demo")
	if err != nil {
		t.Fatalf("find all matches: %v", err)
	}
	seenAll := map[string]struct{}{}
	for _, match := range allMatches {
		seenAll[match.Path] = struct{}{}
	}
	if _, ok := seenAll["local/public.md"]; !ok {
		t.Fatalf("expected public note in all matches, got %+v", allMatches)
	}
	if _, ok := seenAll["local/private.md"]; !ok {
		t.Fatalf("expected private note in all matches, got %+v", allMatches)
	}

	publicMatches, err := idx.FindNoteBlocksByTag(WithPublicVisibility(ctx), "demo")
	if err != nil {
		t.Fatalf("find public matches: %v", err)
	}
	if len(publicMatches) == 0 {
		t.Fatalf("expected public matches")
	}
	for _, match := range publicMatches {
		if match.Path != "local/public.md" {
			t.Fatalf("private note leaked in public context: %+v", publicMatches)
		}
	}
}

func containsTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}
