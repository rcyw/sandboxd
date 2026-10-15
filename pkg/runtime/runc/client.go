// Copyright (c) 2026 Ant Group Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package runc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/inclusionAI/sandboxd/internal/util"
)

// State is the stable subset of `runc list --format json` used by sandboxd.
type State struct {
	ID      string `json:"id"`
	PID     int    `json:"pid"`
	Status  string `json:"status"`
	Bundle  string `json:"bundle"`
	Created string `json:"created"`
}

// Client executes one runc binary against a private state root.
type Client struct {
	binary string
	root   string
}

// commandError carries diagnostics from a runtime which actually exited.
// Launch failures, interrupted commands and local cleanup errors cannot
// establish whether a container exists.
type commandError struct {
	error
	diagnostic string
}

func (e *commandError) Unwrap() error { return e.error }

func NewClient(binary, root string) *Client {
	return &Client{binary: binary, root: root}
}

func (c *Client) command(ctx context.Context, args ...string) ([]byte, error) {
	all := append([]string{"--root", c.root}, args...)
	command := exec.CommandContext(ctx, c.binary, all...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err == nil {
		return stdout.Bytes(), nil
	}
	details := make([]string, 0, 2)
	if output := strings.TrimSpace(stdout.String()); output != "" {
		details = append(details, output)
	}
	if output := strings.TrimSpace(stderr.String()); output != "" {
		details = append(details, output)
	}
	failure := err
	if len(details) > 0 {
		failure = fmt.Errorf("%w: %s", err, strings.Join(details, "\n"))
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return stdout.Bytes(), errors.Join(ctxErr, failure)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() >= 0 {
		return stdout.Bytes(), &commandError{failure, strings.ToLower(stderr.String())}
	}
	return stdout.Bytes(), failure
}

func (c *Client) List(ctx context.Context) ([]State, error) {
	output, err := c.command(ctx, "list", "--format", "json")
	if err != nil {
		return nil, err
	}
	var states []State
	if err := json.Unmarshal(output, &states); err != nil {
		return nil, fmt.Errorf("decode runc list: %w", err)
	}
	return states, nil
}

func (c *Client) State(ctx context.Context, id string) (State, error) {
	output, err := c.command(ctx, "state", id)
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(output, &state); err != nil {
		return State{}, fmt.Errorf("decode runc state: %w", err)
	}
	return state, nil
}

func (c *Client) Kill(ctx context.Context, id, signal string, all bool) error {
	args := []string{"kill"}
	if all {
		args = append(args, "--all")
	}
	args = append(args, id, signal)
	_, err := c.command(ctx, args...)
	return err
}

func (c *Client) Delete(ctx context.Context, id string, force bool) error {
	if id == "" || filepath.Base(id) != id {
		return fmt.Errorf("invalid runc state id %q", id)
	}
	statePath, err := util.JoinWithinRoot(c.root, id)
	if err != nil {
		return err
	}
	args := []string{"delete"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, id)
	_, err = c.command(ctx, args...)
	if !IsNotFound(err) {
		return err
	}
	// A failed runc run can create its directory before writing state.json.
	// The CLI reports that container as absent without removing the directory.
	// Only remove an empty directory after confirmed absence; preserve state
	// files, symlinks and unexpected entries for recovery instead of masking them.
	info, statErr := os.Lstat(statePath)
	if os.IsNotExist(statErr) {
		return nil
	}
	if statErr != nil {
		return fmt.Errorf("inspect runc state directory: %w", statErr)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("runc state path is not a directory: %s", statePath)
	}
	if removeErr := os.Remove(statePath); removeErr != nil && !os.IsNotExist(removeErr) {
		return fmt.Errorf("remove empty runc state directory: %w", removeErr)
	}
	return nil
}

// IsNotFound reports a container-absence diagnostic from an exited runtime.
func IsNotFound(err error) bool {
	var failure *commandError
	return errors.As(err, &failure) && strings.Contains(failure.diagnostic, "container does not exist")
}

// IsNotRunning reports errors that are safe when converging a delete.
func IsNotRunning(err error) bool {
	var failure *commandError
	if !errors.As(err, &failure) {
		return false
	}
	return IsNotFound(err) ||
		strings.Contains(failure.diagnostic, "container is not running") ||
		strings.Contains(failure.diagnostic, "container is stopped") ||
		strings.Contains(failure.diagnostic, "container not running")
}

// IgnoreMissing turns idempotent absence into success.
func IgnoreMissing(err error) error {
	if IsNotFound(err) {
		return nil
	}
	return err
}
