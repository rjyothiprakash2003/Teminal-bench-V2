package main

import (
	"fmt"
	"os"

	"pubguard/internal/analyzer"
)

func main() {
	if err := analyzer.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
