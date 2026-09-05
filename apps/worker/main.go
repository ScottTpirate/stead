package main

import (
	"os"

	"github.com/ScottTpirate/stead/internal/component"
)

func main() {
	if len(os.Args) == 1 {
		os.Exit(runWorker(os.Stderr))
	}
	os.Exit(component.Run("stead-worker", os.Args[1:], os.Stdout, os.Stderr))
}
