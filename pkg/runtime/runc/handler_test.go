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
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/inclusionAI/sandboxd/config"
	"github.com/inclusionAI/sandboxd/internal/runcshim"
	"github.com/inclusionAI/sandboxd/pkg/networkmanager"
	runtimecore "github.com/inclusionAI/sandboxd/pkg/runtime"
	runtimecommon "github.com/inclusionAI/sandboxd/pkg/runtime/internal/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuncCgroupPathUsesRuntimeOwnedChild(t *testing.T) {
	assert.Equal(t, "/sandbox/sbox-test/runc", runcCgroupPath("/sandbox/sbox-test"))
	assert.Empty(t, runcCgroupPath(""))
}

type cancellingOciLoader struct {
	cancel context.CancelFunc
	called bool
}

func (l *cancellingOciLoader) GenerateOci(runtimecore.OciLoadOptions) (string, *runtimecore.Spec, error) {
	l.called = true
	l.cancel()
	return "", &runtimecore.Spec{}, nil
}

func TestRuncStartAlreadyCancelledAllocatesNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := t.TempDir()
	loader := &cancellingOciLoader{cancel: cancel}
	handler := &Handler{sandboxRoot: root, ociLoader: loader}

	err := handler.Start(ctx, runtimecore.StartConfig{ID: "expired"})

	require.ErrorIs(t, err, context.Canceled)
	assert.False(t, loader.called)
	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestRuncStartStopsAfterPreparationCancelsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loader := &cancellingOciLoader{cancel: cancel}
	handler := &Handler{sandboxRoot: t.TempDir(), ociLoader: loader}
	config := runtimecore.StartConfig{
		ID: "expired", CgroupPath: "/private-cgroup",
		Network: &networkmanager.NetResource{
			Interface: &net.Interface{Name: "pv.test"},
			NetNSPath: "/var/run/netns/runc-sbox-expired",
			Lifecycle: networkmanager.InterfaceLifecycleEphemeral,
		},
	}

	err := handler.Start(ctx, config)

	require.True(t, loader.called)
	require.ErrorIs(t, err, context.Canceled)
}

func TestRuncWaitStartedRejectsCancelledReadyMarker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bundle := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bundle, runcshim.InitPIDFile), []byte("42"), 0600))
	require.ErrorIs(t, (&Handler{}).waitStarted(ctx, bundle), context.Canceled)
}

func TestValidateExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runc")
	require.NoError(t, os.WriteFile(path, []byte("binary"), 0644))
	assert.ErrorContains(t, validateExecutable(path, "runc binary"), "executable")

	require.NoError(t, os.Chmod(path, 0755))
	assert.NoError(t, validateExecutable(path, "runc binary"))
	assert.Error(t, validateExecutable(path+"-missing", "runc binary"))
}

func TestConfigureRuncKVM(t *testing.T) {
	spec := &runtimecore.Spec{Linux: &runtimecore.Linux{Resources: &runtimecore.LinuxResources{}}}
	require.NoError(t, configureRuncKVM(spec, os.DevNull))
	require.Len(t, spec.Mounts, 1)
	assert.Equal(t, "/dev/kvm", spec.Mounts[0].Destination)
	assert.Equal(t, os.DevNull, spec.Mounts[0].Source)
	require.Len(t, spec.Linux.Resources.Devices, 1)
	assert.True(t, spec.Linux.Resources.Devices[0].Allow)
	assert.Equal(t, "c", spec.Linux.Resources.Devices[0].Type)

	err := configureRuncKVM(spec, os.DevNull)
	assert.ErrorContains(t, err, "already configured")
}

func TestConfigureRuncKVMRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-device")
	require.NoError(t, os.WriteFile(path, nil, 0644))
	assert.ErrorContains(t, configureRuncKVM(&runtimecore.Spec{}, path), "not a character device")
}

func TestRequireHostFilesystem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filesystems")
	require.NoError(t, os.WriteFile(path, []byte("nodev\toverlay\n\terofs\n"), 0644))
	assert.NoError(t, requireHostFilesystem(path, "overlay"))
	assert.NoError(t, requireHostFilesystem(path, "erofs"))
	assert.ErrorContains(t, requireHostFilesystem(path, "xfs"), "not registered")
}

func TestRuncHandlerListFiltersRuntimeMarker(t *testing.T) {
	root := t.TempDir()
	runcBundle := filepath.Join(root, "sbox-runc")
	otherBundle := filepath.Join(root, "sbox-other")
	require.NoError(t, os.MkdirAll(runcBundle, 0755))
	require.NoError(t, os.MkdirAll(otherBundle, 0755))
	require.NoError(t, runtimecommon.WriteSandboxRuntimeMarker(runcBundle, config.RuntimeNameRunc))
	require.NoError(t, runtimecommon.WriteSandboxRuntimeMarker(otherBundle, config.RuntimeNameRunsc))
	handler := &Handler{client: &fakeRuncClient{states: []State{
		{ID: "sbox-runc", PID: 10, Status: "running", Bundle: runcBundle},
		{ID: "sbox-other", PID: 11, Status: "running", Bundle: otherBundle},
	}}}
	states, err := handler.List(context.Background())
	require.NoError(t, err)
	require.Len(t, states, 1)
	assert.Equal(t, "sbox-runc", states[0].ID)
	assert.Equal(t, runtimecore.SandboxStatusRunning, states[0].Status)
}

func TestRuncHandlerWaitReadsDurableExit(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "sbox-wait")
	require.NoError(t, os.MkdirAll(bundle, 0755))
	exitedAt := time.Now().UTC().Round(0)
	require.NoError(t, runcshim.WriteExit(filepath.Join(bundle, runcshim.ExitFile), runcshim.ExitRecord{
		Started:  true,
		ExitCode: 31,
		ExitedAt: exitedAt,
	}))
	handler := &Handler{sandboxRoot: root}
	exit, err := handler.Wait(context.Background(), "sbox-wait")
	require.NoError(t, err)
	assert.Equal(t, 31, exit.ExitCode)
	assert.Equal(t, exitedAt, exit.ExitedAt)
}

func TestRuncHandlerWaitReturnsStartupError(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "sbox-failed")
	require.NoError(t, os.MkdirAll(bundle, 0755))
	require.NoError(t, runcshim.WriteExit(filepath.Join(bundle, runcshim.ExitFile), runcshim.ExitRecord{
		ExitCode:     125,
		RuntimeError: "invalid OCI spec",
	}))
	handler := &Handler{sandboxRoot: root}
	_, err := handler.Wait(context.Background(), "sbox-failed")
	assert.EqualError(t, err, "invalid OCI spec")
}

type fakeRuncClient struct {
	states    []State
	state     State
	stateErr  error
	killErr   error
	deleteErr error
}

func (f *fakeRuncClient) List(context.Context) ([]State, error) {
	return f.states, nil
}

func (f *fakeRuncClient) State(context.Context, string) (State, error) {
	return f.state, f.stateErr
}

func (f *fakeRuncClient) Kill(context.Context, string, string, bool) error {
	return f.killErr
}

func (f *fakeRuncClient) Delete(context.Context, string, bool) error {
	return f.deleteErr
}

func TestRuncDeleteRetainsFilesUntilRuntimeDeletionSucceeds(t *testing.T) {
	for _, failure := range []string{"missing-binary", "permission-denied", "runtime-error"} {
		t.Run(failure, func(t *testing.T) {
			const id = "sbox-delete-retry"
			handler := &Handler{sandboxRoot: t.TempDir(), storageRoot: t.TempDir()}
			binary := filepath.Join(t.TempDir(), "runc")
			switch failure {
			case "permission-denied":
				require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0600))
			case "runtime-error":
				require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\necho 'helper not found' >&2\nexit 1\n"), 0755))
			}
			stateRoot := t.TempDir()
			statePath := filepath.Join(stateRoot, id)
			require.NoError(t, os.Mkdir(statePath, 0700))
			handler.client = NewClient(binary, stateRoot)
			bundle := filepath.Join(handler.sandboxRoot, id)
			files := []string{
				filepath.Join(bundle, runcRootfsDir, "retained"),
				filepath.Join(bundle, runcEROFSMountsDir, "0", runcEROFSContentDir, "retained"),
				filepath.Join(handler.storageRoot, id, "upper", "retained"),
			}
			for _, path := range files {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
				require.NoError(t, os.WriteFile(path, []byte("owned data"), 0600))
			}
			unmounts := 0
			originalUnmount := unmountRuncPath
			t.Cleanup(func() { unmountRuncPath = originalUnmount })
			unmountRuncPath = func(string) error { unmounts++; return nil }

			err := handler.Delete(context.Background(), id)
			require.Error(t, err)
			assert.Zero(t, unmounts, "failed runtime deletion must not tear down its mounts")
			assert.DirExists(t, statePath)
			for _, path := range files {
				assert.FileExists(t, path)
			}

			// Restore a runtime which confirms this container is absent, then
			// retry through the same production Handler and Client.
			require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\necho 'container does not exist' >&2\nexit 1\n"), 0755))
			require.NoError(t, os.Chmod(binary, 0755))
			require.NoError(t, handler.Delete(context.Background(), id))
			assert.Positive(t, unmounts)
			assert.NoDirExists(t, statePath)
			assert.NoDirExists(t, filepath.Join(handler.storageRoot, id))
			for _, path := range files {
				assert.NoFileExists(t, path)
			}
		})
	}
}

func TestRuncWaitStoppedDoesNotTreatMissingBinaryAsStopped(t *testing.T) {
	handler := &Handler{client: NewClient(filepath.Join(t.TempDir(), "missing-runc"), t.TempDir())}
	stopped, err := handler.waitStopped(context.Background(), "sbox-test", time.Second)
	assert.False(t, stopped)
	assert.True(t, errors.Is(err, syscall.ENOENT))
}

func TestRuncOrphanReconciliationRetainsStorageOnRuntimeFailure(t *testing.T) {
	const id = "sbox-orphan-retry"
	binary := filepath.Join(t.TempDir(), "missing-runc")
	handler := &Handler{
		sandboxRoot: t.TempDir(), storageRoot: t.TempDir(),
		client: NewClient(binary, t.TempDir()),
	}
	storage := filepath.Join(handler.storageRoot, id)
	require.NoError(t, os.Mkdir(storage, 0700))
	retained := filepath.Join(storage, "retained")
	require.NoError(t, os.WriteFile(retained, []byte("owned data"), 0600))
	unmounts := 0
	originalUnmount := unmountRuncPath
	t.Cleanup(func() { unmountRuncPath = originalUnmount })
	unmountRuncPath = func(string) error { unmounts++; return nil }

	require.ErrorIs(t, handler.reconcileOrphans(), syscall.ENOENT)
	assert.Zero(t, unmounts)
	assert.FileExists(t, retained)

	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\necho 'container does not exist' >&2\nexit 1\n"), 0755))
	require.NoError(t, handler.reconcileOrphans())
	assert.NoDirExists(t, storage)
}
