// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package rv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/storage/index"
)

var (
	// ErrFailed is the error returned when compilation fails.
	ErrFailed = errors.New("failed to compile")

	header         = color.New(color.FgHiWhite, color.Bold).SprintFunc()
	fileName       = color.New(color.FgHiCyan).SprintFunc()
	errorMsg       = color.New(color.FgHiRed).SprintFunc()
	testName       = color.New(color.FgHiBlue, color.Bold).SprintFunc()
	skippedTest    = color.New(color.FgHiWhite).SprintFunc()
	failedTest     = color.New(color.FgHiRed).SprintFunc()
	successfulTest = color.New(color.FgHiGreen).SprintFunc()

	format string
)

const (
	formatJSON  = "json"
	formatPlain = "plain"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "rv",
		Short:         "Generate a role-based view of the Cerbos policies",
		RunE:          doRun,
		Args:          cobra.ExactArgs(1),
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&format, "format", "f", "", "Output format (valid values: json,plain)")

	return cmd
}

func doRun(cmd *cobra.Command, args []string) error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	idx, err := index.Build(ctx, os.DirFS(args[0]))
	if err != nil {
		idxErr := new(index.BuildError)
		if errors.As(err, &idxErr) {
			return displayLintErrors(cmd, idxErr)
		}

		return fmt.Errorf("failed to open directory %s: %w", args[0], err)
	}

	res, err := analyse(ctx, idx)
	if err != nil {
		compErr := new(compile.ErrorList)
		if !errors.As(err, compErr) {
			return fmt.Errorf("analysis failed: %w", err)
		}

		displayCompileErrors(cmd, *compErr)
	}

	displayResult(cmd, res)

	return nil
}

func displayLintErrors(cmd *cobra.Command, errs *index.BuildError) error {
	switch strings.ToLower(format) {
	case formatJSON:
		if err := outputJSON(cmd, map[string]*index.BuildError{"lintErrors": errs}); err != nil {
			return err
		}

		return ErrFailed
	case formatPlain:
		color.NoColor = true
	}

	if len(errs.DuplicateDefs) > 0 {
		cmd.Println(header("Duplicate definitions"))
		for _, dd := range errs.DuplicateDefs {
			cmd.Printf("%s is a duplicate of %s\n", fileName(dd.File), fileName(dd.OtherFile))
		}
		cmd.Println()
	}

	if len(errs.MissingImports) > 0 {
		cmd.Println(header("Missing Imports"))
		for _, mi := range errs.MissingImports {
			cmd.Printf("%s: %s\n", fileName(mi.ImportingFile), errorMsg(mi.Desc))
		}
		cmd.Println()
	}

	if len(errs.LoadFailures) > 0 {
		cmd.Println(header("Load failures"))
		for _, lf := range errs.LoadFailures {
			cmd.Printf("%s: %s\n", fileName(lf.File), errorMsg(lf.Err.Error()))
		}
		cmd.Println()
	}

	if len(errs.Disabled) > 0 {
		cmd.Println(header("Disabled policies"))
		for _, d := range errs.Disabled {
			cmd.Println(fileName(d))
		}
		cmd.Println()
	}

	return ErrFailed
}

func displayCompileErrors(cmd *cobra.Command, errs compile.ErrorList) error {
	switch strings.ToLower(format) {
	case formatJSON:
		if err := outputJSON(cmd, map[string]compile.ErrorList{"compileErrors": errs}); err != nil {
			return err
		}

		return ErrFailed
	case formatPlain:
		color.NoColor = true
	}

	cmd.Println(header("Compilation errors"))
	for _, err := range errs {
		cmd.Printf("%s: %s (%s)\n", fileName(err.File), errorMsg(err.Description), err.Err.Error())
	}

	return ErrFailed
}

func displayResult(cmd *cobra.Command, result map[string]*RoleInfo) error {
	switch strings.ToLower(format) {
	case formatJSON:
		return outputJSON(cmd, result)
	case formatPlain:
		color.NoColor = true
	}

	cmd.Println(header("Role Capabilities"))
	for role, roleInfo := range result {
		cmd.Printf("role=%s", role)
		cmd.Println()

		for resource, resInfo := range roleInfo.ResourceActions {
			for version, actions := range resInfo.VersionActions {
				cmd.Printf("\tresource=%s (%s)", resource, version)
				cmd.Println()

				for action, actionInfo := range actions {
					cmd.Printf("\t\taction=%s", action)
					if actionInfo.DerivedRole != "" {
						cmd.Printf(" (through derived role %q)", actionInfo.DerivedRole)
						cmd.Println()
					}
					cmd.Println()

					if actionInfo.DerivedRoleCond != "" {
						cmd.Printf("\t\t\tDerived role condition=%s", actionInfo.DerivedRoleCond)
						cmd.Println()
					}

					if actionInfo.PolicyCond != "" {
						cmd.Printf("\t\t\tPolicy condition=%s", actionInfo.PolicyCond)
						cmd.Println()
					}
					cmd.Println()
				}
				cmd.Println()
			}
			cmd.Println()
		}
	}

	return nil
}

func outputJSON(cmd *cobra.Command, val interface{}) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(val)
}
