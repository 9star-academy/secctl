package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/9star-academy/secctl/internal/cli"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	app := cli.New(version, os.Stdout, os.Stderr, os.Stdin)
	return app.Run(ctx, os.Args[1:])
}
