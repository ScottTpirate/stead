package main

import (
	"os"

	"github.com/ScottTpirate/stead/internal/component"
)

func main() {
	os.Exit(component.Run("stead-worker", os.Args[1:], os.Stdout, os.Stderr))
}
