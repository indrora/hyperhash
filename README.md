# hyperhash

A fast, parallel file hashing utility with support for multiple hash algorithms and verification capabilities. Compatible with standard hashing tools like `sha256sum`, `md5sum`, and similar utilities.

## Features

- **Parallel processing**: Multi-threaded hashing for improved performance on multi-core systems
- **Glob pattern support**: Use wildcards to match files (e.g., `*.txt`, `**/*.go`)
- **Standard compatibility**: Output format compatible with `sha256sum`, `md5sum`, and other standard tools

## Installation

```bash
go install github.com/indrora/hyperhash@latest
```

Or clone and build locally:

```bash
git clone https://github.com/indrora/hyperhash.git
cd hyperhash
go build
```

## Usage

```
Usage: hyperhash [options] <file1> <file2> ...
Options:
  -h, --help          Show help message
  -p, --progress      Show progress bars
  -q, --quiet         Do not print any non-error output
  -t, --type string   The type of hash to compute (e.g., sha256, md5) (default "sha256")
  -v, --verbose       Enable verbose output
  -c, --verify        Verify the computed hashes against existing hash values
      --workers int   Number of worker goroutines to use (default is number of CPU cores)
```

Sum using the default (SHA256)
```
hyperhash [-t <type>] <filespec> [<filespec> ...]
```

Verify a hash file.
```
hyperhash -t <type> -c <hashfile> [<hashfile> ...]
```

## Performance

I'll let this speak for itself. 

Macbook Pro M3 Max 14 core. 

```
$ ll
total 147714384
-rw-r--r--@ 1 indrora  staff   488B Jun 29  2025 sha256-0578f229f23ad620e123654fd0b4708405e7af3629ec1aecf3f553f54e06bc40
-rw-r--r--@ 1 indrora  staff   416B Oct  6 13:48 sha256-14ee8f0bef4328b56aeb8425fbeedf1d2ac731fe701b9124600cc31e6d6cae23
-rw-r--r--@ 1 indrora  staff   1.6K Jun 29  2025 sha256-1e65450c30670713aa47fe23e8b9662bdf4065e81cc8e3cbfaa98924fcc0d320
[ ... rest of directory listing omitted ...]
-rw-r--r--@ 1 indrora  staff    11K Aug  7  2025 sha256-f60356777647e927149cbd4c0ec1314a90caba9400ad205ddc4ce47ed001c2d6
-rw-r--r--@ 1 indrora  staff   7.1K Oct  9 01:45 sha256-fa6710a93d78da62641e192361344be7a8c0a1c3737f139cf89f20ce1626b99c
-rw-r--r--@ 1 indrora  staff   489B Oct  6 15:07 sha256-fead963410119421fd15e7c2ac71cb83f9c028384b990acb3a2441b5955b09ef
$ time sha256sum sha256* > sums
sha256sum sha256* > sums  27.70s user 12.44s system 98% cpu 40.661 total
$ time ~/src/hyperhash/hyperhash -t sha256 -c sums
Hashing 25 files with SHA256...
sha256-0578f229f23ad620e123654fd0b4708405e7af3629ec1aecf3f553f54e06bc40: OK
sha256-14ee8f0bef4328b56aeb8425fbeedf1d2ac731fe701b9124600cc31e6d6cae23: OK
sha256-1e65450c30670713aa47fe23e8b9662bdf4065e81cc8e3cbfaa98924fcc0d320: OK
[ ... rest of output omitted ... ]
sha256-f60356777647e927149cbd4c0ec1314a90caba9400ad205ddc4ce47ed001c2d6: OK
sha256-fa6710a93d78da62641e192361344be7a8c0a1c3737f139cf89f20ce1626b99c: OK
sha256-fead963410119421fd15e7c2ac71cb83f9c028384b990acb3a2441b5955b09ef: OK
~/src/hyperhash/hyperhash -t sha256 -c sums  29.17s user 9.83s system 334% cpu 11.644 total
$ du -sh .
 70G   .
```

