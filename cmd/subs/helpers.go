package subs

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/lilendian0x00/xray-knife/v11/database"
	"github.com/lilendian0x00/xray-knife/v11/utils/exitcode"
	"github.com/spf13/cobra"
)

// usageErr is an error about how the command was invoked; the CLI exits
// with the usage code (2) for it.
func usageErr(msg string) error {
	return exitcode.New(exitcode.Usage, errors.New(msg))
}

// validateSubscriptionURL accepts only absolute http(s) URLs with a host:
// anything else (a local path, ftp://, a typo without a scheme) would be
// stored and then fail on every fetch.
func validateSubscriptionURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid URL %q: only http:// and https:// subscription URLs are supported", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid URL %q: missing host", raw)
	}
	return nil
}

// bindSubscriptionIDFlags registers --sub-id (canonical, the name `http
// --sub-id` uses) and --id (deprecated alias) on the same variable.
func bindSubscriptionIDFlags(cmd *cobra.Command, dst *int64, usage string) {
	cmd.Flags().Int64Var(dst, "sub-id", 0, usage)
	cmd.Flags().Int64Var(dst, "id", 0, "Deprecated alias for --sub-id")
	_ = cmd.Flags().MarkDeprecated("id", "use --sub-id")
	_ = cmd.RegisterFlagCompletionFunc("sub-id", completeSubscriptionIDs)
	_ = cmd.RegisterFlagCompletionFunc("id", completeSubscriptionIDs)
}

// completeSubscriptionIDs offers stored subscription IDs, described by their
// remark or URL. It reads the database read-only and never migrates it.
func completeSubscriptionIDs(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var out []string
	for _, s := range database.CompletionSubscriptions() {
		id := strconv.FormatInt(s.ID, 10)
		if !strings.HasPrefix(id, toComplete) {
			continue
		}
		desc := s.URL
		if s.Remark.Valid && s.Remark.String != "" {
			desc = s.Remark.String
		}
		if !s.Enabled {
			desc += " (disabled)"
		}
		out = append(out, id+"\t"+desc)
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// knownProtocols are the protocol names stored in the configs table.
var knownProtocols = []string{"vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria2",
	"hysteria", "tuic", "anytls", "ssh", "mtproto"}

func completeProtocols(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return knownProtocols, cobra.ShellCompDirectiveNoFileComp
}

// printJSON writes v as indented JSON to stdout.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
