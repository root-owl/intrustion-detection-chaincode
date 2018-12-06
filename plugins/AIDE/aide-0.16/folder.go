package aide

import (
	"strings"
)

const (
	EntryEndupIndex = "\n"
	EntryFileIndexPrefix = "File:"
	EntryFolderIndexPrefix = "Directory:"
)

type Entry struct{
	RawResult []string
}

func (entry *Entry) String() string {
	return strings.Join(entry.RawResult,"")
}

type FolderDetailEntry struct {
	RawResult	[]string

	Path		string
	Mtime		string
	Ctime		string
	Linkcount	string
}

func (folder *FolderDetailEntry) String() string {
	return strings.Join(folder.RawResult, "")
}

type FileDetailEntry struct {
	RawResult	[]string

	Path		string
	Mtime		string
	Ctime		string
	Linkcount	string
}

func (file *FileDetailEntry) String() string {
	return strings.Join(file.RawResult,"")
}

func NewFolderDetailEntry(result []string) (*FolderDetailEntry) {
	return &FolderDetailEntry{RawResult:result}
}

func NewFileDetailEntry(result []string) (*FileDetailEntry) {
	return &FileDetailEntry{RawResult:result}
}

func GetDetailsEntries(result []string) ([]*Entry) {

	var line string

	var isStartEntry bool = false
	var rawEntryResult []string

	var detailEntries = []*Entry{}

	for _, line = range result {
		if isStartEntry {
			if line == EntryEndupIndex {
				entry := &Entry{RawResult:rawEntryResult}
				detailEntries = append(detailEntries, entry)

				isStartEntry = false
				rawEntryResult = []string{}
			} else {
				rawEntryResult = append(rawEntryResult, line)
			}
		} else {
			if strings.HasPrefix(line, EntryFolderIndexPrefix) ||
				strings.HasPrefix(line, EntryFileIndexPrefix) {
					rawEntryResult = []string{line}
					isStartEntry = true
			}
		}
	}

	if len(detailEntries) == 0 {
		return nil
	} else {
		return detailEntries
	}
}

func GetDetailEntries(detailResult []string) ([]*FolderDetailEntry, []*FileDetailEntry) {
	var entries []*Entry
	var folders = []*FolderDetailEntry{}
	var files = []*FileDetailEntry{}

	entries = GetDetailsEntries(detailResult)

	if entries == nil {
		return nil, nil
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.RawResult[0], EntryFolderIndexPrefix) {
			folderEntry := &FolderDetailEntry{RawResult:entry.RawResult}
			folders = append(folders, folderEntry)
		} else if strings.HasPrefix(entry.RawResult[0], EntryFileIndexPrefix) {
			fileEntry := &FileDetailEntry{RawResult:entry.RawResult}
			files = append(files, fileEntry)
		}
	}

	return folders, files
}
