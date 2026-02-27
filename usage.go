package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

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
