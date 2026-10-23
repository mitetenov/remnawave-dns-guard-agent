package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	agent "github.com/mitetenov/remnawave-dns-guard-agent"
)

func main() { os.Exit(run()) }

func run() int {
	log.SetFlags(0)
	if len(os.Args) == 2 && os.Args[1] == "--healthcheck" {
		if agent.Healthy(agent.HeartbeatPath, time.Now()) {
			return 0
		}
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if len(os.Args) != 1 {
		log.Print("invalid_settings")
		return 2
	}
	settings, err := agent.SettingsFromEnv()
	if err != nil {
		log.Print("invalid_settings")
		return 2
	}
	worker, err := agent.New(settings)
	if err != nil {
		log.Print("invalid_settings")
		return 2
	}
	worker.Run(ctx)
	return 0
}
