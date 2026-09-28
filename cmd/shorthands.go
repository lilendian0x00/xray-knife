package cmd

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// canonicalShorthands maps a shorthand letter to the ONE long flag name it may
// bind to, anywhere in the command tree. Adding an entry is a deliberate
// CLI-surface decision: cmd/shorthands_test.go fails the build on any
// deviation, so a new flag cannot quietly claim a letter another command
// already uses for something else.
//
// Letters absent from this map may not be used as shorthands at all. If a flag
// needs one, either it takes a free letter (added here) or it stays long-only.
// Long-only is the default for anything not typed interactively week to week.
var canonicalShorthands = map[string]string{
	"a": "addr",
	"b": "body",
	"c": "config",
	"d": "mdelay",
	"e": "insecure",
	"f": "file",
	"h": "help", // added by cobra
	"i": "stdin",
	"j": "json",
	"l": "limit",
	"m": "method",
	"o": "out",
	"p": "port",
	"r": "remark",
	"s": "subnets",
	"t": "threads",
	"n": "count",
	"u": "url",
	"v": "verbose",
	"w": "workers",
	"x": "type",
	"y": "yes",
	"z": "core",
	"R": "rotate",
	"S": "speedtest",
	"V": "version",
}

// grandfathered lists shorthand bindings that predate canonicalShorthands and
// have not been realigned yet. Keys are "<command path> -<letter>".
//
// This list only shrinks. Each realignment task deletes its own entries, and
// the test fails if an entry stops violating (so nothing goes stale).
//
// It is empty: the v11 realignment cleared every legacy binding. Do not add
// entries — fix the flag instead.
var grandfathered = map[string]bool{}

// removedShorthands maps a letter that v10 accepted but v11 does not to the
// instruction a user needs. pflag's own error ("unknown shorthand flag") says
// nothing about what the letter used to do, which is the whole question a
// user hitting it has.
var removedShorthands = map[string]string{
	"k": "-k was --only-speedtest; use --only-speedtest",
	"C": "-C was --config; use -c",
	"E": "-E was --insecure; use --insecure (-e on http and proxy; cfscanner gets -e in v12)",
	"P": "-P was --port; use -p",
	"g": "-g was --uuid; use --uuid",
	"I": "-I was --inbound-config; use --inbound-config",
	"n": "-n was --concurrency; use --threads (-n is now --count, which this command does not take)",
	"i": "-i was --shuffle-ip on cfscanner; use --shuffle-ip (elsewhere -i is --stdin, which this command does not take)",
	"e": "-e was --shuffle-subnet on cfscanner; use --shuffle-subnet",
	"a": "-a was --amount on http and --user-agent on subs; use the long flag",
	"r": "-r was --rip on http and --retry on cfscanner; use the long flag",
	"s": "-s was --sort on http; use --sort",
	"u": "-u was --timeout on cfscanner and --transport on proxy; use the long flag",
	"d": "-d was --download-mb on cfscanner; use --download-mb",
	"m": "-m was --upload-mb on cfscanner; use --upload-mb",
	"b": "-b was --batch on proxy; use --batch",
	"j": "-j was --inbound on proxy; use --inbound",
	"t": "-t was --rotate on proxy; use -R/--rotate (on proxy, -t becomes --threads in v12)",
	"p": "-p was --speedtest on http and cfscanner; use -S",
}

var unknownShorthandRE = regexp.MustCompile(`unknown shorthand flag: '(.)' in`)

// flagErrorFunc turns pflag's bare "unknown shorthand flag" into a migration
// instruction for letters the v11 realignment moved. Anything else passes
// through untouched.
//
// Several of these letters are still valid shorthands on other commands; the
// hint only fires where pflag actually rejected the letter, so a valid use is
// never intercepted.
//
// Every flag error is returned as a usageError, so the process exits with the
// usage code (2).
func flagErrorFunc(cmd *cobra.Command, err error) error {
	m := unknownShorthandRE.FindStringSubmatch(err.Error())
	if m == nil {
		return usageError{err}
	}
	hint, ok := removedShorthands[m[1]]
	if !ok {
		return usageError{err}
	}
	return usageError{fmt.Errorf("%w\n\nshorthand flags were realigned in v11: %s\nsee MIGRATION-v11.md", err, hint)}
}

// visitShorthands walks the command tree and calls fn once for every flag that
// declares a shorthand, using the flag set the command itself owns (local +
// its own persistent flags). Inherited flags are skipped so a parent's
// persistent flag is reported once, against the parent.
func visitShorthands(root *cobra.Command, fn func(path string, f *pflag.Flag)) {
	root.InitDefaultHelpFlag()
	root.InitDefaultVersionFlag()

	inherited := map[string]bool{}
	root.InheritedFlags().VisitAll(func(f *pflag.Flag) { inherited[f.Name] = true })

	root.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Shorthand == "" || inherited[f.Name] {
			return
		}
		fn(root.CommandPath(), f)
	})

	for _, child := range root.Commands() {
		visitShorthands(child, fn)
	}
}
