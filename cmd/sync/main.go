package main

import (
	"context"
	"fmt"
	"os"

	"gwiki/internal/config"
	"gwiki/internal/syncer"
)

func main() {
	cfg := config.Load()
	output, err := syncer.Run(context.Background(), cfg.RepoPath)
	if output != "" {
		fmt.Print(output)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
