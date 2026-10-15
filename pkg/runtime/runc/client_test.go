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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientListUsesPrivateRoot(t *testing.T) {
	dir := t.TempDir()
	trace := filepath.Join(dir, "args")
	binary := filepath.Join(dir, "runc")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + trace + "\nprintf '[{\"id\":\"sbox-one\",\"pid\":42,\"status\":\"running\"}]'\n"
	require.NoError(t, os.WriteFile(binary, []byte(script), 0755))

	states, err := NewClient(binary, "/run/private-runc").List(context.Background())
	require.NoError(t, err)
	require.Len(t, states, 1)
	assert.Equal(t, "sbox-one", states[0].ID)
	assert.Equal(t, 42, states[0].PID)
	args, err := os.ReadFile(trace)
	require.NoError(t, err)
	assert.Equal(t, "--root\n/run/private-runc\nlist\n--format\njson\n", string(args))
}

func TestClientListIgnoresSuccessfulRuntimeStderr(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "runc")
	script := "#!/bin/sh\necho 'load container: container does not exist' >&2\nprintf '[{\"id\":\"sbox-one\",\"status\":\"running\"}]'\n"
	require.NoError(t, os.WriteFile(binary, []byte(script), 0755))

	states, err := NewClient(binary, dir).List(context.Background())
	require.NoError(t, err)
	require.Len(t, states, 1)
	assert.Equal(t, "sbox-one", states[0].ID)
	assert.Equal(t, "running", states[0].Status)
}

func TestClientIncludesRuntimeFailureDetail(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "runc")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\necho precise-runc-error >&2\nexit 1\n"), 0755))

	_, err := NewClient(binary, dir).State(context.Background(), "sbox-missing")
	require.Error(t, err)
	assert.ErrorContains(t, err, "precise-runc-error")
}

func TestRuncErrorClassification(t *testing.T) {
	assert.False(t, IsNotFound(errors.New("container does not exist")))
	assert.False(t, IsNotRunning(errors.New("container is stopped")))
	assert.Error(t, IgnoreMissing(errors.New("not found")))
	assert.Error(t, IgnoreMissing(assert.AnError))
}

func TestClientClassifiesRuntimeContainerErrors(t *testing.T) {
	for _, test := range []struct {
		message  string
		missing  bool
		inactive bool
	}{
		{"container does not exist", true, true},
		{`time="2026-10-15T00:00:00Z" level=error msg="container does not exist"`, true, true},
		{"container not running", false, true},
		{"container is not running", false, true},
		{"container is stopped", false, true},
		{"open /private/state.json: no such file or directory", false, false},
		{"helper binary not found", false, false},
	} {
		t.Run(test.message, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "runc")
			script := "#!/bin/sh\ncat >&2 <<'RUNC_DIAGNOSTIC'\n" + test.message + "\nRUNC_DIAGNOSTIC\nexit 1\n"
			require.NoError(t, os.WriteFile(binary, []byte(script), 0755))
			_, err := NewClient(binary, t.TempDir()).State(context.Background(), "sbox-test")
			require.Error(t, err)
			assert.Equal(t, test.missing, IsNotFound(err))
			assert.Equal(t, test.inactive, IsNotRunning(err))
		})
	}
}

func TestClientLaunchFailuresAreNotContainerAbsence(t *testing.T) {
	for _, executable := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "permission-denied"}[executable], func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "runc")
			if executable {
				require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0600))
			}
			client := NewClient(binary, t.TempDir())
			_, stateErr := client.State(context.Background(), "sbox-test")
			for _, err := range []error{stateErr, client.Delete(context.Background(), "sbox-test", true)} {
				require.Error(t, err)
				assert.False(t, IsNotFound(err))
				assert.False(t, IsNotRunning(err))
				assert.Error(t, IgnoreMissing(err))
			}
		})
	}
}

func TestClientCancellationPreservesRuntimeDiagnosticWithoutConfirmingAbsence(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(t.TempDir(), "runc")
	script := "#!/bin/sh\necho 'container does not exist' >&2\nprintf ready > \"$2/ready\"\nexec /bin/sleep 30\n"
	require.NoError(t, os.WriteFile(binary, []byte(script), 0755))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := NewClient(binary, root).State(ctx, "sbox-test")
		done <- err
	}()
	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(root, "ready"))
		return err == nil
	}, 5*time.Second, time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		assert.ErrorContains(t, err, "container does not exist")
		assert.False(t, IsNotFound(err))
		assert.False(t, IsNotRunning(err))
	case <-time.After(5 * time.Second):
		t.Fatal("runtime command did not stop after cancellation")
	}
}

func missingContainerClient(t *testing.T, root string) *Client {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "runc")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\necho 'container does not exist' >&2\nexit 1\n"), 0755))
	return NewClient(binary, root)
}

func TestClientDeleteReclaimsMissingContainerEmptyState(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "sbox-expired")
	require.NoError(t, os.Mkdir(state, 0700))

	err := missingContainerClient(t, root).Delete(context.Background(), "sbox-expired", true)

	require.NoError(t, IgnoreMissing(err))
	assert.NoDirExists(t, state)
}

func TestClientDeletePreservesNonemptyMissingContainerState(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "sbox-expired")
	require.NoError(t, os.Mkdir(state, 0700))
	file := filepath.Join(state, "state.json")
	require.NoError(t, os.WriteFile(file, []byte("important state"), 0600))

	err := missingContainerClient(t, root).Delete(context.Background(), "sbox-expired", true)

	require.Error(t, IgnoreMissing(err))
	data, readErr := os.ReadFile(file)
	require.NoError(t, readErr)
	assert.Equal(t, "important state", string(data))
}

func TestClientDeleteRejectsStateSymlinkAndEscapingIDs(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))
	client := missingContainerClient(t, root)
	for _, id := range []string{"linked", "../outside", ".", "", "nested/container"} {
		t.Run(id, func(t *testing.T) {
			require.Error(t, IgnoreMissing(client.Delete(context.Background(), id, true)))
			assert.DirExists(t, outside)
		})
	}
	info, err := os.Lstat(filepath.Join(root, "linked"))
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink)
}

func TestClientDeleteMissingStateIsIdempotent(t *testing.T) {
	client := missingContainerClient(t, t.TempDir())
	require.NoError(t, IgnoreMissing(client.Delete(context.Background(), "absent", true)))
}

func TestClientDeleteCannotReclaimStateWithoutRuntimeConfirmation(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "sbox-expired")
	require.NoError(t, os.Mkdir(state, 0700))
	client := NewClient(filepath.Join(t.TempDir(), "missing-runc"), root)

	require.Error(t, client.Delete(context.Background(), "sbox-expired", true))
	assert.DirExists(t, state)
}
