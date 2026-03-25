package main

import (
	"runtime"
	"time"

	"fmt"
	"io"
	"os"
	"sync/atomic"

	"slices"
	"strings"

	"github.com/indrora/toil"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/pflag"

	"github.com/earthboundkid/versioninfo/v2"
)

type hashable struct {
	Path      string
	Hash      []byte
	CheckHash []byte
	Valid     bool
}

var oFile io.Writer = os.Stdout

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
		// Version
		version *bool = pflag.BoolP("version", "V", false, "Show version information")
		// Progress bars?
		progress *bool = pflag.BoolP("progress", "p", false, "Show progress bars")
		// Files to hash (or checksum files to verify)
		inputGlob []string
	)

	// Diagnostic messages and errors go to stderr; This specifies if we should print to stdout or io.Discard for messages about hash verification results.

	versioninfo.AddFlag(nil)

	pflag.Parse()

	if *help {
		usage()

	}
	if *version {
		fmt.Println(versioninfo.Short())
		os.Exit(0)
	}

	if *quiet {
		oFile = io.Discard
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

	// Start the actual hashing.

	counter := atomic.Int64{}
	counter.Store(0)
	mismatch := atomic.Bool{}
	mismatch.Store(false) // Start with a clean slate for mismatch status

	// Compute the hash for each file
	cHash := func(h hashable) (hashable, error) {
		var hashValue []byte

		hasher := hashFunc.New()

		counter.Add(1)

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
			mismatch.CompareAndSwap(false, h.Valid == false)
		} else {
			h.Valid = true
		}
		return h, nil

	}

	finished := make(chan bool) // For progress bar to know when we're done

	if *progress {
		// Progress bar is run in a separate goroutine
		// since internally it uses a mutex.
		go func() {
			bar := progressbar.NewOptions64(int64(len(files)),
				progressbar.OptionFullWidth(),
				progressbar.OptionSetDescription("Hashing files"),
				progressbar.OptionThrottle(50*time.Millisecond),
				progressbar.OptionSetPredictTime(true),
				progressbar.OptionShowCount(),
			)

			bar.RenderBlank()
			if *verify {
				bar.Describe("Verifying files")
			} else {
				bar.Describe("Hashing files")
			}

			last := counter.Load()
			for {
				select {
				default:
					if counter.Load() != last {
						last = counter.Load()
						bar.Set64(last)
					} else {
						// Don't burn CPU if nothing has changed since the last check
						runtime.Gosched()
					}
				case <-finished:
					bar.Exit()
					bar.Clear()
					return
				}
			}
		}()
	}

	files, err = toil.ParallelTransform(files, cHash, toil.Options{}.WithWorkers(*numWorkers))

	finished <- true
	close(finished)

	if !*quiet {
		fmt.Fprintf(os.Stderr, "Complete: %v files hashed\n", counter.Load())
	}
	if err != nil {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "Error computing hashes: %v\n", err)
		}
		os.Exit(1)
	}

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
				}
			}
		} else {
			if h.Hash == nil {
				continue
			}
			fmt.Fprintf(os.Stdout, "%x  %s\n", h.Hash, h.Path)
		}
	}
	if *verify && mismatch.Load() {
		os.Exit(1)
	} else {
		os.Exit(0)
	}

}
