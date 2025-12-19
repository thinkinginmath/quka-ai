package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/quka-ai/quka-ai/cmd/migrate"
	"github.com/quka-ai/quka-ai/cmd/service"
	_ "github.com/quka-ai/quka-ai/pkg/plugins/selfhost"
)

func main() {
	root := &cobra.Command{
		Use:   "quka",
		Short: "QukaAI - Knowledge Base and RAG System",
		Long: `QukaAI is a lightweight, user-friendly RAG (Retrieval Augmented Generation) system
that helps you build your second brain.

Available Commands:
  service   Start the main HTTP service
  process   Start the background process worker
  migrate   Manage database migrations`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	root.AddCommand(
		service.NewCommand(),
		service.NewProcessCommand(),
		migrate.NewCommand(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
