package main

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/indrora/toil"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/pflag"

	// Register the hash functions we want to support
	_ "crypto/md5"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	_ "golang.org/x/crypto/blake2b"
	_ "golang.org/x/crypto/blake2s"
	_ "golang.org/x/crypto/md4"
	_ "golang.org/x/crypto/ripemd160"
)

type hashable struct {
	Path      string
	Hash      []byte
	CheckHash []byte
	Valid     bool
}

var hashFuncs = map[string]crypto.Hash{
	"MD4":    crypto.MD4,
	"MD5":    crypto.MD5,
	"SHA1":   crypto.SHA1,
	"SHA224": crypto.SHA224,
	"SHA256": crypto.SHA256,
	"SHA384": crypto.SHA384,
	"SHA512": crypto.SHA512,

	"RIPEMD160": crypto.RIPEMD160,

	"SHA3-224": crypto.SHA3_224,
	"SHA3-256": crypto.SHA3_256,
	"SHA3-384": crypto.SHA3_384,
	"SHA3-512": crypto.SHA3_512,

	"BLAKE2B-256": crypto.BLAKE2b_256,
	"BLAKE2B-384": crypto.BLAKE2b_384,
	"BLAKE2B-512": crypto.BLAKE2b_512,
	"BLAKE2S-256": crypto.BLAKE2s_256,
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options] <file1> <file2> ...\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	pflag.PrintDefaults()

	// Print a list of available hash functions
	fmt.Println("\nAvailable hash functions:")
	for name := range hashFuncs {
		// print it lowercase for user-friendliness
		lowerName := strings.ToLower(name)
		fmt.Printf("  - %s\n", lowerName)
	}

	os.Exit(0)
}

func main() {
	var (
		// helpfunc
		help *bool = pflag.BoolP("help", "h", false, "Show help message")
		// TODO: Should we require this? Or continue to default to SHA256 if not provided?
		hashType *string = pflag.StringP("type", "t", "sha256", "The type of hash to compute (e.g., sha256, md5)")
		// Most of the UNIX utilities use -c/--check for this functionality, so we should probably follow that convention.
		// TODO: Is there a POSIX standard for this? If so, we should follow that.
		verify *bool = pflag.BoolP("verify", "c", false, "Verify the computed hashes against existing hash values")
		// Could use a shorthand.
		numWorkers *int = pflag.Int("workers", 0, "Number of worker goroutines to use (default is number of CPU cores)")
		// More "debug" but useful for smaller sets of files.
		verbose *bool = pflag.BoolP("verbose", "v", false, "Enable verbose output")
		// Quiet
		quiet *bool = pflag.BoolP("quiet", "q", false, "Do not print any non-error output")

		// Progress bars?
		progress *bool = pflag.BoolP("progress", "p", false, "Show progress bars")
		// Files to hash (or checksum files to verify)
		inputGlob []string
	)

	// Diagnostic messages and errors go to stderr; This specifies if we should print to stdout or io.Discard for messages about hash verification results.
	oFile := os.Stdout

	pflag.Parse()

	if *help {
		usage()

	}

	inputGlob = pflag.Args()

	if len(inputGlob) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No input files specified")
		usage()
	}

	*hashType = strings.ToUpper(*hashType)

	if _, ok := hashFuncs[*hashType]; !ok {
		fmt.Fprintf(os.Stderr, "Error: Unsupported hash type: %s\n", *hashType)
		usage()
	}

	hashFunc := hashFuncs[*hashType]

	var files []hashable

	paths, err := collectToHash(inputGlob)
	if err != nil {

		fmt.Fprintf(os.Stderr, "Error while collecting files: %v\n", err)

		os.Exit(1)
	}

	if *verify {
		files, err = checksums2hashables(paths)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error collecting checksums: %v\n", err)
			os.Exit(1)
		}
	} else {
		files = files2hashables(paths)
	}

	files = slices.DeleteFunc(files, func(h hashable) bool {

		return h.Path == "" // no file on disk...
	})

	if !*quiet {
		fmt.Fprintf(os.Stderr, "Hashing %d files with %s...\n", len(files), *hashType)
	}

	var bar *progressbar.ProgressBar = nil

	if !*quiet && *progress {

		bar := progressbar.Default(int64(len(files)), "")
		if *verify {
			bar.Describe("Verifying files")
		} else {
			bar.Describe("Hashing files")
		}
		defer bar.Close()
	}
	// Compute the hash for each file
	cHash := func(h hashable) (hashable, error) {
		var hashValue []byte

		hasher := hashFunc.New()

		if bar != nil {
			bar.Add(1)
		}

		// Don't hash directories, symlinks, named pipes, or sockets
		info, err := os.Stat(h.Path)
		if err != nil {
			return h, err
		}

		if info.IsDir() {
			h.Hash = hashValue
			return h, nil
		}

		// If it's a symlink, check if the file exists.
		if info.Mode()&os.ModeSymlink != 0 {
			targetPath, err := os.Readlink(h.Path)
			if err != nil {
				return h, nil
			}
			if _, err := os.Stat(targetPath); os.IsNotExist(err) {
				h.Hash = hashValue
				return h, nil
			}
		}

		file, err := os.Open(h.Path)
		if err != nil {
			return h, err
		}
		defer file.Close()

		if _, err := io.Copy(hasher, file); err != nil {
			return h, err
		}
		h.Hash = hasher.Sum(nil)
		if *verify {
			h.Valid = slices.Equal(h.CheckHash, h.Hash)
		} else {
			h.Valid = true
		}
		return h, nil

	}

	files, err = toil.ParallelTransform(files, cHash, toil.Options{}.WithWorkers(*numWorkers))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error computing hashes: %v\n", err)
		os.Exit(1)
	}

	pass := true

	// Output the results
	for _, h := range files {

		if *verify {
			if *verbose {
				fmt.Fprintf(os.Stderr, "%s: computed hash %x, expected hash %x\n", h.Path, h.Hash, h.CheckHash)
			} else {

				if h.Valid {
					fmt.Fprintf(oFile, "%s: OK\n", h.Path)
				} else {
					fmt.Fprintf(oFile, "%s: MISMATCH\n", h.Path)
					pass = false
				}
			}
		} else {
			if h.Hash == nil {
				continue
			}
			fmt.Fprintf(os.Stdout, "%x  %s\n", h.Hash, h.Path)
		}
	}
	if *verify && !pass {
		os.Exit(1)
	}

}

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
