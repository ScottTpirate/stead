package main

import (
	"os"

	"github.com/ScottTpirate/stead/internal/component"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "dev-web":
			os.Exit(runDevWeb(os.Args[2:], os.Stderr))
		case "dev-certificate":
			os.Exit(runDevCertificate(os.Args[2:], os.Stderr))
		case "dev-probe":
			os.Exit(runDevProbe(os.Args[2:], os.Stderr))
		}
	}
	os.Exit(component.Run("stead-api", os.Args[1:], os.Stdout, os.Stderr))
}
