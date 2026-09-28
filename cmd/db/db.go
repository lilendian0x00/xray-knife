// Package db implements `xray-knife db`, maintenance for the local SQLite
// database.
package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
	"github.com/spf13/cobra"
)

// DBCmd groups the database maintenance subcommands.
var DBCmd = &cobra.Command{
	Use:   "db",
	Short: "Inspect and maintain the local database (stats, prune, vacuum, backup)",
	Long: `Maintenance for the SQLite database that stores subscriptions, fetched
configs, HTTP test runs and CF scanner results.

The database lives at $XRAY_KNIFE_HOME/xray-knife.db (default
~/.xray-knife/xray-knife.db); --db points every command at another file.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		_ = cmd.Help()
	},
}

func init() {
	DBCmd.AddCommand(newStatsCmd(), newPruneCmd(), newVacuumCmd(), newBackupCmd(), newMigrateCmd())
}

func newStatsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Show row counts, file size and schema version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, path, err := openExisting()
			if err != nil {
				return err
			}
			defer db.Close()
			st, err := database.GetStatsDB(db, path)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(st)
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(w, "Path\t%s\n", st.Path)
			fmt.Fprintf(w, "Size\t%s (WAL %s)\n", humanBytes(st.SizeBytes), humanBytes(st.WALBytes))
			if st.SchemaDirty {
				fmt.Fprintf(w, "Schema version\t%d (DIRTY: see 'xray-knife db migrate --help')\n", st.SchemaVersion)
			} else {
				fmt.Fprintf(w, "Schema version\t%d\n", st.SchemaVersion)
			}
			fmt.Fprintf(w, "Subscriptions\t%d (%d enabled)\n", st.Subscriptions, st.EnabledSubs)
			fmt.Fprintf(w, "Configs\t%d (%d one-off)\n", st.Configs, st.OneOffConfigs)
			fmt.Fprintf(w, "HTTP test runs\t%d (%d results)\n", st.HttpTestRuns, st.HttpTestResults)
			if st.OldestRunStart != "" {
				fmt.Fprintf(w, "Test runs span\t%s .. %s\n", st.OldestRunStart, st.LatestRunStart)
			}
			fmt.Fprintf(w, "CF scan results\t%d\n", st.CfScanResults)
			if st.LastSubscriptionF != "" {
				fmt.Fprintf(w, "Last subscription fetch\t%s\n", st.LastSubscriptionF)
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVarP(&asJSON, "json", "j", false, "Print as JSON")
	return cmd
}

func newPruneCmd() *cobra.Command {
	var (
		opts   database.PruneOptions
		runs   string
		cfgs   string
		cf     string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Delete old test runs, stale configs and old CF scan results",
		Long: `Deletes history that keeps growing otherwise:

  --runs-older-than   HTTP test runs (and their results) started before this age,
                      always keeping the newest --keep-runs runs
  --configs-unseen    configs no subscription (or one-off fetch) returned for this
                      long (off unless given: configs are your library)
  --cf-older-than     CF scanner results last scanned before this age (off unless given)

Ages accept Go durations plus a "d" day suffix: 30d, 12h, 90d. Pass 0 to skip
a part. With no flags only test runs older than 30 days are pruned. Use
--dry-run to see what would be deleted.

Examples:
  xray-knife db prune --dry-run
  xray-knife db prune --runs-older-than 14d --keep-runs 5
  xray-knife db prune --runs-older-than 0 --configs-unseen 60d --dry-run`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if opts.RunsOlderThan, err = parseAge(runs); err != nil {
				return fmt.Errorf("--runs-older-than: %w", err)
			}
			if opts.ConfigsUnseenFor, err = parseAge(cfgs); err != nil {
				return fmt.Errorf("--configs-unseen: %w", err)
			}
			if opts.CfScansOlderThan, err = parseAge(cf); err != nil {
				return fmt.Errorf("--cf-older-than: %w", err)
			}
			if opts.KeepRuns < 0 {
				return fmt.Errorf("--keep-runs must not be negative")
			}
			res, err := database.Prune(opts)
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(res)
			}
			verb := "Deleted"
			if opts.DryRun {
				verb = "Would delete"
			}
			customlog.Printf(customlog.Success, "%s %d test run(s) with %d result(s), %d config(s), %d stale config source(s), %d CF scan result(s).\n",
				verb, res.Runs, res.Results, res.Configs, res.Sources, res.CfScans)
			if !opts.DryRun && res.Runs+res.Configs+res.CfScans > 0 {
				customlog.Printf(customlog.Info, "Run 'xray-knife db vacuum' to reclaim the disk space.\n")
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&runs, "runs-older-than", "30d", "Delete HTTP test runs older than this (0 = keep all)")
	f.IntVar(&opts.KeepRuns, "keep-runs", 10, "Always keep this many of the newest test runs")
	f.StringVar(&cfgs, "configs-unseen", "0", "Delete configs not returned by any fetch for this long, e.g. 60d (0 = keep all)")
	f.StringVar(&cf, "cf-older-than", "0", "Delete CF scan results older than this (0 = keep all)")
	f.BoolVar(&opts.DryRun, "dry-run", false, "Only report what would be deleted")
	f.BoolVarP(&asJSON, "json", "j", false, "Print the counts as JSON")
	return cmd
}

func newVacuumCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vacuum",
		Short: "Rebuild the database file to reclaim unused space",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, path, err := openExisting()
			if err != nil {
				return err
			}
			defer db.Close()
			before, _ := os.Stat(path)
			if err := database.VacuumDB(db); err != nil {
				return err
			}
			after, _ := os.Stat(path)
			if before != nil && after != nil {
				customlog.Printf(customlog.Success, "Vacuumed %s: %s -> %s\n", path, humanBytes(before.Size()), humanBytes(after.Size()))
			} else {
				customlog.Printf(customlog.Success, "Vacuumed %s\n", path)
			}
			return nil
		},
	}
}

func newBackupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "backup <file>",
		Short: "Write a consistent copy of the database to a new file",
		Long: `Writes a consistent, compacted copy of the database (SQLite VACUUM INTO).
Safe to run while other xray-knife commands use the database, and on a
database whose migration state is dirty. The target file must not exist; it is
created with mode 0600 (it holds subscription URLs and credentials).

Example:
  xray-knife db backup ~/xray-knife-$(date +%F).db`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, _, err := openExisting()
			if err != nil {
				return err
			}
			defer db.Close()
			if err := database.BackupDB(db, args[0]); err != nil {
				return err
			}
			customlog.Printf(customlog.Success, "Backup written to %s\n", args[0])
			return nil
		},
	}
}

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Show or repair the schema migration state",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show the recorded schema version (without migrating)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, path, err := openExisting()
			if err != nil {
				return err
			}
			defer db.Close()
			v, dirty, err := database.MigrationStatus(db.DB)
			if err != nil {
				return err
			}
			latest, _ := database.LatestVersion()
			state := "clean"
			if dirty {
				state = "DIRTY (a migration was interrupted)"
			}
			fmt.Printf("database: %s\nversion:  %d of %d (%s)\n", path, v, latest, state)
			return nil
		},
	}
	force := &cobra.Command{
		Use:   "force <version|none>",
		Short: "Mark <version> as applied and clean, without running migrations",
		Long: `Records <version> as the current, clean schema version without running any
migration. This is the manual way out of a "dirty" database after an
interrupted migration: back the file up ('xray-knife db backup'), check which
of that migration's changes exist, then force the version they correspond to.
The next command applies whatever migrations come after it.

Versions are numbered from 1. "none" records that no migration has run, so
the next command applies all of them (only right for a database whose tables
do not exist yet).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := parseForceVersion(args[0])
			if err != nil {
				return exitcode.New(exitcode.Usage, err)
			}
			db, path, err := openExisting()
			if err != nil {
				return err
			}
			defer db.Close()
			if err := database.ForceMigrationVersion(db.DB, v); err != nil {
				return err
			}
			if v < 0 {
				customlog.Printf(customlog.Success, "Schema version of %s cleared (no migrations recorded).\n", path)
			} else {
				customlog.Printf(customlog.Success, "Schema version of %s forced to %d.\n", path, v)
			}
			return nil
		},
	}
	cmd.AddCommand(status, force)
	return cmd
}

// openExisting opens the configured database for maintenance: it must
// exist, and it is not migrated, so stats, vacuum, backup and the migrate
// commands also work on a dirty database.
func openExisting() (*sqlx.DB, string, error) {
	path, err := database.ResolvePath()
	if err != nil {
		return nil, "", err
	}
	db, err := database.OpenExisting(path)
	if err != nil {
		return nil, path, err
	}
	return db, path, nil
}

// parseForceVersion reads a `db migrate force` argument: an existing
// migration version, or "none" (-1, golang-migrate's NilVersion).
func parseForceVersion(arg string) (int, error) {
	if arg == "none" {
		return -1, nil
	}
	v, err := strconv.Atoi(arg)
	if err != nil {
		return 0, fmt.Errorf("version must be a migration number or \"none\", got %q", arg)
	}
	latest, _ := database.LatestVersion()
	switch {
	case v == 0:
		return 0, errors.New(`there is no migration 0: versions start at 1; use "none" to record that no migration has run`)
	case v < 0:
		return 0, fmt.Errorf("version must be a migration number or \"none\", got %q", arg)
	case uint(v) > latest:
		return 0, fmt.Errorf("version %d is newer than this binary knows (%d)", v, latest)
	}
	return v, nil
}

// parseAge reads a duration that may use a "d" (day) suffix. "0" disables.
func parseAge(s string) (time.Duration, error) {
	if s == "" || s == "0" {
		return 0, nil
	}
	if n := len(s); n > 1 && s[n-1] == 'd' {
		days, err := strconv.ParseFloat(s[:n-1], 64)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid age %q", s)
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid age %q (use e.g. 30d or 12h)", s)
	}
	return d, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
