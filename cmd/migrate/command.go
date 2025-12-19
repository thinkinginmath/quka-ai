package migrate

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/quka-ai/quka-ai/app/core"
	"github.com/quka-ai/quka-ai/app/store/sqlstore"
)

type Options struct {
	ConfigPath string
	DryRun     bool
}

func (o *Options) AddFlags(flagSet *pflag.FlagSet) {
	flagSet.StringVarP(&o.ConfigPath, "config", "c", "", "config file path")
	flagSet.BoolVar(&o.DryRun, "dry-run", false, "show pending migrations without executing")
}

// NewCommand creates the migrate command with subcommands
func NewCommand() *cobra.Command {
	opts := &Options{}

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Database migration management",
		Long: `Run database migrations for QukaAI.

This command manages database schema migrations. Migrations are tracked
in the quka_schema_migrations table to ensure each migration runs only once.

Examples:
  # Run all pending migrations
  ./quka migrate -c config.toml

  # Show pending migrations without running them
  ./quka migrate -c config.toml --dry-run

  # Check migration status
  ./quka migrate status -c config.toml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMigrate(opts)
		},
	}

	opts.AddFlags(cmd.Flags())

	// Add subcommands
	cmd.AddCommand(newStatusCommand(opts))

	return cmd
}

// runMigrate executes pending migrations
func runMigrate(opts *Options) error {
	if opts.ConfigPath == "" {
		return fmt.Errorf("config file is required: use -c flag")
	}

	fmt.Println("🔄 Loading configuration...")
	cfg := core.MustLoadBaseConfig(opts.ConfigPath)

	fmt.Println("🔌 Connecting to database...")
	provider := sqlstore.MustSetup(cfg.Database.Master, cfg.Database.Slaves...)()

	if opts.DryRun {
		fmt.Println("\n📋 Dry run mode - showing pending migrations:")
		return showPendingMigrations(provider)
	}

	fmt.Println("🚀 Running migrations...")
	if err := provider.Install(); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	fmt.Println("✅ Migrations completed successfully!")
	return nil
}

// showPendingMigrations lists migrations that would be run
func showPendingMigrations(provider *sqlstore.Provider) error {
	pending, err := provider.GetPendingMigrations()
	if err != nil {
		return err
	}

	if len(pending) == 0 {
		fmt.Println("No pending migrations.")
		return nil
	}

	fmt.Printf("\nFound %d pending migration(s):\n\n", len(pending))
	for i, name := range pending {
		fmt.Printf("  %d. %s\n", i+1, name)
	}
	fmt.Println()

	return nil
}

// newStatusCommand creates the status subcommand
func newStatusCommand(opts *Options) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		Long:  "Display which migrations have been applied and which are pending.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(opts)
		},
	}
}

// runStatus shows the current migration status
func runStatus(opts *Options) error {
	if opts.ConfigPath == "" {
		return fmt.Errorf("config file is required: use -c flag")
	}

	fmt.Println("🔄 Loading configuration...")
	cfg := core.MustLoadBaseConfig(opts.ConfigPath)

	fmt.Println("🔌 Connecting to database...")
	provider := sqlstore.MustSetup(cfg.Database.Master, cfg.Database.Slaves...)()

	// Get all migrations and their status
	allMigrations, err := provider.GetAllMigrationFiles()
	if err != nil {
		return fmt.Errorf("failed to get migration files: %w", err)
	}

	executedMigrations, err := provider.GetExecutedMigrations()
	if err != nil {
		return fmt.Errorf("failed to get executed migrations: %w", err)
	}

	// Build a map for quick lookup
	executedMap := make(map[string]int64)
	for _, m := range executedMigrations {
		executedMap[m.Filename] = m.ExecutedAt
	}

	fmt.Println("\n📊 Migration Status:")
	fmt.Println("====================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tFILENAME\tEXECUTED AT")
	fmt.Fprintln(w, "------\t--------\t-----------")

	pendingCount := 0
	for _, filename := range allMigrations {
		if executedAt, ok := executedMap[filename]; ok {
			t := time.Unix(executedAt, 0).Format("2006-01-02 15:04:05")
			fmt.Fprintf(w, "✅ Applied\t%s\t%s\n", filename, t)
		} else {
			fmt.Fprintf(w, "⏳ Pending\t%s\t-\n", filename)
			pendingCount++
		}
	}
	w.Flush()

	fmt.Printf("\nTotal: %d migrations (%d applied, %d pending)\n",
		len(allMigrations), len(allMigrations)-pendingCount, pendingCount)

	return nil
}
