package main

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
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

func main() {
	var (
		hashType   *string = pflag.String("hash-type", "sha256", "The type of hash to compute (e.g., sha256, md5)")
		verify     *bool   = pflag.Bool("verify", false, "Verify the computed hashes against existing hash values")
		numWorkers *int    = pflag.Int("workers", 0, "Number of worker goroutines to use (default is number of CPU cores)")
		verbose    *bool   = pflag.BoolP("verbose", "v", false, "Enable verbose output")
		inputGlob  []string
		help       *bool = pflag.BoolP("help", "h", false, "Show help message")
	)
	pflag.Parse()

	if *help {
		pflag.Usage()

		// Print a list of available hash functions
		fmt.Println("\nAvailable hash functions:")
		for name := range hashFuncs {
			// print it lowercase for user-friendliness
			lowerName := strings.ToLower(name)
			fmt.Printf("  - %s\n", lowerName)
		}

		return
	}

	inputGlob = pflag.Args()

	if len(inputGlob) == 0 {
		panic("At least one input glob pattern must be provided")
	}

	*hashType = strings.ToUpper(*hashType)

	if _, ok := hashFuncs[*hashType]; !ok {
		panic("Unsupported hash type: " + *hashType)
	}

	hashFunc := hashFuncs[*hashType]

	var files []hashable
	if *verify {
		for _, name := range inputGlob {
			filesFromFile, err := collectFilesFromFile(name)
			if err != nil {
				panic(fmt.Sprintf("Error collecting files from '%s': %v", name, err))
			}
			files = append(files, filesFromFile...)
		}
	} else {
		var err error
		files, err = collectFiles(inputGlob)
		if err != nil {
			panic(fmt.Sprintf("Error collecting files: %v", err))
		}
	}

	bar := progressbar.Default(int64(len(files)), "")
	if *verify {
		bar.Describe("Verifying files")
	} else {
		bar.Describe("Hashing files")
	}

	// Compute the hash for each file
	cHash := func(h hashable) (hashable, error) {
		var hashValue []byte

		hasher := hashFunc.New()

		bar.Add(1)

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

	files, err := toil.ParallelTransform(files, cHash, toil.Options{}.WithWorkers(*numWorkers))
	if err != nil {
		panic(fmt.Sprintf("Error computing hashes: %v", err))
	}

	// Output the results
	for _, h := range files {

		if *verify {
			if *verbose {
				fmt.Printf("%s: computed hash %x, expected hash %x\n", h.Path, h.Hash, h.CheckHash)
			} else {

				if h.Valid {
					fmt.Printf("%s: OK\n", h.Path)
				} else {
					fmt.Printf("%s: MISMATCH\n", h.Path)
				}
			}
		} else {
			if h.Hash == nil {
				continue
			}
			fmt.Printf("%x  %s\n", h.Hash, h.Path)
		}
	}
}

func collectFiles(patterns []string) ([]hashable, error) {
	var files []hashable
	for _, pattern := range patterns {
		root, pat := doublestar.SplitPattern(pattern)
		err := doublestar.GlobWalk(os.DirFS(root), pat, func(path string, d fs.DirEntry) error {
			if d.IsDir() {
				return nil
			}
			files = append(files, hashable{Path: root + "/" + path})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error processing glob pattern '%s': %v", pattern, err)
		}
	}
	return files, nil
}

func collectFilesFromFile(filePath string) ([]hashable, error) {
	var files []hashable
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening file '%s': %v", filePath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// The format is expected to be: <hash> <path>
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue // Skip comments and empty lines
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue // Skip lines that don't match the expected format
		}

		filePatth := parts[0]
		hashValue, err := hex.DecodeString(filePatth)
		if err != nil {
			continue // Skip lines with invalid hash values
		}

		files = append(files, hashable{Path: parts[1], CheckHash: hashValue})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file '%s': %v", filePath, err)
	}
	return files, nil
}
