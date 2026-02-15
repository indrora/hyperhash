package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

func collectToHash(globs []string) ([]string, error) {
	var files []string
	for _, pattern := range globs {
		matches, err := doublestar.FilepathGlob(pattern)
		if err != nil {
			return nil, fmt.Errorf("error globbing pattern '%s': %v", pattern, err)
		}
		files = append(files, matches...)
	}
	return files, nil
}

func files2hashables(files []string) []hashable {
	hashables := make([]hashable, len(files))
	for i, file := range files {
		// Check that it isn't a directory, symlink, named pipe, or socket. If it is, we won't hash it.
		info, err := os.Stat(file)

		if err != nil {
			continue
		}

		if info.IsDir() || info.Mode()&os.ModeNamedPipe != 0 || info.Mode()&os.ModeSocket != 0 {
			continue
		}
		// If it's a symlink, check if the file exists. If it doesn't, we won't hash it.
		if info.Mode()&os.ModeSymlink != 0 {
			targetPath, err := os.Readlink(file)
			if err != nil {
				continue
			}
			if _, err := os.Stat(targetPath); os.IsNotExist(err) {
				continue
			}
		}

		hashables[i] = hashable{Path: file}
	}
	return hashables
}

func checksums2hashables(files []string) ([]hashable, error) {
	var hashables []hashable
	for _, file := range files {
		hashablesFromFile, err := collectChecksums(file)
		if err != nil {
			return nil, fmt.Errorf("error collecting checksums from '%s': %v", file, err)
		}
		hashables = append(hashables, hashablesFromFile...)
	}
	return hashables, nil
}

func collectChecksums(filePath string) ([]hashable, error) {
	var files []hashable
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file '%s': %v", filePath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	hashPattern := regexp.MustCompile(`^([a-fA-F0-9]+)\s+(.+)$`)

	// The format is expected to be: <hash> <path>
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue // Skip comments and empty lines
		}

		// Split the line into hash and path.

		matches := hashPattern.FindStringSubmatch(line)
		if len(matches) != 3 {
			continue // Skip lines that don't match the expected format
		}

		fileHash := matches[1]
		filePath := matches[2]

		if filePath == "" {
			continue // Skip lines with empty file path
		}

		hashValue, err := hex.DecodeString(fileHash)
		if err != nil {
			continue // Skip lines with invalid hash values
		}

		files = append(files, hashable{Path: filePath, CheckHash: hashValue})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file '%s': %v", filePath, err)
	}
	return files, nil
}
