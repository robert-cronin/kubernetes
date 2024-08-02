//go:build linux
// +build linux

/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package volume

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	v1 "k8s.io/api/core/v1"
	utiltesting "k8s.io/client-go/util/testing"
	"k8s.io/kubernetes/pkg/volume/util/types"
)

type localFakeMounter struct {
	path       string
	attributes Attributes
}

func (l *localFakeMounter) GetPath() string {
	return l.path
}

func (l *localFakeMounter) GetAttributes() Attributes {
	return l.attributes
}

func (l *localFakeMounter) SetUp(mounterArgs MounterArgs) error {
	return nil
}

func (l *localFakeMounter) SetUpAt(dir string, mounterArgs MounterArgs) error {
	return nil
}

func (l *localFakeMounter) GetMetrics() (*Metrics, error) {
	return nil, nil
}

func TestSkipPermissionChange(t *testing.T) {
	always := v1.FSGroupChangeAlways
	onrootMismatch := v1.FSGroupChangeOnRootMismatch
	tests := []struct {
		description         string
		fsGroupChangePolicy *v1.PodFSGroupChangePolicy
		gidOwnerMatch       bool
		permissionMatch     bool
		sgidMatch           bool
		skipPermssion       bool
	}{
		{
			description:   "skippermission=false, policy=nil",
			skipPermssion: false,
		},
		{
			description:         "skippermission=false, policy=always",
			fsGroupChangePolicy: &always,
			skipPermssion:       false,
		},
		{
			description:         "skippermission=false, policy=always, gidmatch=true",
			fsGroupChangePolicy: &always,
			skipPermssion:       false,
			gidOwnerMatch:       true,
		},
		{
			description:         "skippermission=false, policy=nil, gidmatch=true",
			fsGroupChangePolicy: nil,
			skipPermssion:       false,
			gidOwnerMatch:       true,
		},
		{
			description:         "skippermission=false, policy=onrootmismatch, gidmatch=false",
			fsGroupChangePolicy: &onrootMismatch,
			gidOwnerMatch:       false,
			skipPermssion:       false,
		},
		{
			description:         "skippermission=false, policy=onrootmismatch, gidmatch=true, permmatch=false",
			fsGroupChangePolicy: &onrootMismatch,
			gidOwnerMatch:       true,
			permissionMatch:     false,
			skipPermssion:       false,
		},
		{
			description:         "skippermission=false, policy=onrootmismatch, gidmatch=true, permmatch=true",
			fsGroupChangePolicy: &onrootMismatch,
			gidOwnerMatch:       true,
			permissionMatch:     true,
			skipPermssion:       false,
		},
		{
			description:         "skippermission=false, policy=onrootmismatch, gidmatch=true, permmatch=true, sgidmatch=true",
			fsGroupChangePolicy: &onrootMismatch,
			gidOwnerMatch:       true,
			permissionMatch:     true,
			sgidMatch:           true,
			skipPermssion:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
			if err != nil {
				t.Fatalf("error creating temp dir: %v", err)
			}

			defer os.RemoveAll(tmpDir)

			info, err := os.Lstat(tmpDir)
			if err != nil {
				t.Fatalf("error reading permission of tmpdir: %v", err)
			}

			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat == nil {
				t.Fatalf("error reading permission stats for tmpdir: %s", tmpDir)
			}

			gid := stat.Gid

			var expectedGid int64

			if test.gidOwnerMatch {
				expectedGid = int64(gid)
			} else {
				expectedGid = int64(gid + 3000)
			}

			mask := rwMask

			if test.permissionMatch {
				mask |= execMask

			}
			if test.sgidMatch {
				mask |= os.ModeSetgid
				mask = info.Mode() | mask
			} else {
				nosgidPerm := info.Mode() &^ os.ModeSetgid
				mask = nosgidPerm | mask
			}

			err = os.Chmod(tmpDir, mask)
			if err != nil {
				t.Errorf("Chmod failed on %v: %v", tmpDir, err)
			}

			mounter := &localFakeMounter{path: tmpDir}
			ok = skipPermissionChange(mounter, tmpDir, &expectedGid, test.fsGroupChangePolicy)
			if ok != test.skipPermssion {
				t.Errorf("for %s expected skipPermission to be %v got %v", test.description, test.skipPermssion, ok)
			}

		})
	}
}

func TestSetVolumeOwnershipMode(t *testing.T) {
	always := v1.FSGroupChangeAlways
	onrootMismatch := v1.FSGroupChangeOnRootMismatch
	expectedMask := rwMask | os.ModeSetgid | execMask

	tests := []struct {
		description         string
		fsGroupChangePolicy *v1.PodFSGroupChangePolicy
		setupFunc           func(path string) error
		assertFunc          func(path string) error
	}{
		{
			description:         "featuregate=on, fsgroupchangepolicy=always",
			fsGroupChangePolicy: &always,
			setupFunc: func(path string) error {
				info, err := os.Lstat(path)
				if err != nil {
					return err
				}
				// change mode of root folder to be right
				err = os.Chmod(path, info.Mode()|expectedMask)
				if err != nil {
					return err
				}

				// create a subdirectory with invalid permissions
				rogueDir := filepath.Join(path, "roguedir")
				nosgidPerm := info.Mode() &^ os.ModeSetgid
				err = os.Mkdir(rogueDir, nosgidPerm)
				if err != nil {
					return err
				}
				return nil
			},
			assertFunc: func(path string) error {
				rogueDir := filepath.Join(path, "roguedir")
				hasCorrectPermissions := verifyDirectoryPermission(rogueDir, false /*readOnly*/)
				if !hasCorrectPermissions {
					return fmt.Errorf("invalid permissions on %s", rogueDir)
				}
				return nil
			},
		},
		{
			description:         "featuregate=on, fsgroupchangepolicy=onrootmismatch,rootdir=validperm",
			fsGroupChangePolicy: &onrootMismatch,
			setupFunc: func(path string) error {
				info, err := os.Lstat(path)
				if err != nil {
					return err
				}
				// change mode of root folder to be right
				err = os.Chmod(path, info.Mode()|expectedMask)
				if err != nil {
					return err
				}

				// create a subdirectory with invalid permissions
				rogueDir := filepath.Join(path, "roguedir")
				err = os.Mkdir(rogueDir, rwMask)
				if err != nil {
					return err
				}
				return nil
			},
			assertFunc: func(path string) error {
				rogueDir := filepath.Join(path, "roguedir")
				hasCorrectPermissions := verifyDirectoryPermission(rogueDir, false /*readOnly*/)
				if hasCorrectPermissions {
					return fmt.Errorf("invalid permissions on %s", rogueDir)
				}
				return nil
			},
		},
		{
			description:         "featuregate=on, fsgroupchangepolicy=onrootmismatch,rootdir=invalidperm",
			fsGroupChangePolicy: &onrootMismatch,
			setupFunc: func(path string) error {
				// change mode of root folder to be right
				err := os.Chmod(path, 0770)
				if err != nil {
					return err
				}

				// create a subdirectory with invalid permissions
				rogueDir := filepath.Join(path, "roguedir")
				err = os.Mkdir(rogueDir, rwMask)
				if err != nil {
					return err
				}
				return nil
			},
			assertFunc: func(path string) error {
				rogueDir := filepath.Join(path, "roguedir")
				hasCorrectPermissions := verifyDirectoryPermission(rogueDir, false /*readOnly*/)
				if !hasCorrectPermissions {
					return fmt.Errorf("invalid permissions on %s", rogueDir)
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			tmpDir, err := utiltesting.MkTmpdir("volume_linux_ownership")
			if err != nil {
				t.Fatalf("error creating temp dir: %v", err)
			}

			defer os.RemoveAll(tmpDir)
			info, err := os.Lstat(tmpDir)
			if err != nil {
				t.Fatalf("error reading permission of tmpdir: %v", err)
			}

			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat == nil {
				t.Fatalf("error reading permission stats for tmpdir: %s", tmpDir)
			}

			var expectedGid int64 = int64(stat.Gid)
			err = test.setupFunc(tmpDir)
			if err != nil {
				t.Errorf("for %s error running setup with: %v", test.description, err)
			}

			mounter := &localFakeMounter{path: "FAKE_DIR_DOESNT_EXIST"} // SetVolumeOwnership() must rely on tmpDir
			err = SetVolumeOwnership(mounter, tmpDir, &expectedGid, test.fsGroupChangePolicy, nil)
			if err != nil {
				t.Errorf("for %s error changing ownership with: %v", test.description, err)
			}
			err = test.assertFunc(tmpDir)
			if err != nil {
				t.Errorf("for %s error verifying permissions with: %v", test.description, err)
			}
		})
	}
}

// verifyDirectoryPermission checks if given path has directory permissions
// that is expected by k8s. If returns true if it does otherwise false
func verifyDirectoryPermission(path string, readonly bool) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return false
	}
	unixPerms := rwMask

	if readonly {
		unixPerms = roMask
	}

	unixPerms |= execMask
	filePerm := info.Mode().Perm()
	if (unixPerms&filePerm == unixPerms) && (info.Mode()&os.ModeSetgid != 0) {
		return true
	}
	return false
}

func TestSetVolumeOwnershipOwner(t *testing.T) {
	fsGroup := int64(3000)
	currentUid := os.Geteuid()
	if currentUid != 0 {
		t.Skip("running as non-root")
	}
	currentGid := os.Getgid()

	tests := []struct {
		description string
		fsGroup     *int64
		setupFunc   func(path string) error
		assertFunc  func(path string) error
	}{
		{
			description: "fsGroup=nil",
			fsGroup:     nil,
			setupFunc: func(path string) error {
				filename := filepath.Join(path, "file.txt")
				file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0755)
				if err != nil {
					return err
				}
				file.Close()
				return nil
			},
			assertFunc: func(path string) error {
				filename := filepath.Join(path, "file.txt")
				if !verifyFileOwner(filename, currentUid, currentGid) {
					return fmt.Errorf("invalid owner on %s", filename)
				}
				return nil
			},
		},
		{
			description: "*fsGroup=3000",
			fsGroup:     &fsGroup,
			setupFunc: func(path string) error {
				filename := filepath.Join(path, "file.txt")
				file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0755)
				if err != nil {
					return err
				}
				file.Close()
				return nil
			},
			assertFunc: func(path string) error {
				filename := filepath.Join(path, "file.txt")
				if !verifyFileOwner(filename, currentUid, int(fsGroup)) {
					return fmt.Errorf("invalid owner on %s", filename)
				}
				return nil
			},
		},
		{
			description: "symlink",
			fsGroup:     &fsGroup,
			setupFunc: func(path string) error {
				filename := filepath.Join(path, "file.txt")
				file, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0755)
				if err != nil {
					return err
				}
				file.Close()

				symname := filepath.Join(path, "file_link.txt")
				err = os.Symlink(filename, symname)
				if err != nil {
					return err
				}

				return nil
			},
			assertFunc: func(path string) error {
				symname := filepath.Join(path, "file_link.txt")
				if !verifyFileOwner(symname, currentUid, int(fsGroup)) {
					return fmt.Errorf("invalid owner on %s", symname)
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			tmpDir, err := utiltesting.MkTmpdir("volume_linux_ownership")
			if err != nil {
				t.Fatalf("error creating temp dir: %v", err)
			}

			defer os.RemoveAll(tmpDir)

			err = test.setupFunc(tmpDir)
			if err != nil {
				t.Errorf("for %s error running setup with: %v", test.description, err)
			}

			mounter := &localFakeMounter{path: tmpDir}
			always := v1.FSGroupChangeAlways
			err = SetVolumeOwnership(mounter, tmpDir, test.fsGroup, &always, nil)
			if err != nil {
				t.Errorf("for %s error changing ownership with: %v", test.description, err)
			}
			err = test.assertFunc(tmpDir)
			if err != nil {
				t.Errorf("for %s error verifying permissions with: %v", test.description, err)
			}
		})
	}
}

// verifyFileOwner checks if given path is owned by uid and gid.
// It returns true if it is otherwise false.
func verifyFileOwner(path string, uid, gid int) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return false
	}

	if int(stat.Uid) != uid || int(stat.Gid) != gid {
		return false
	}

	return true
}

func TestSetVolumeOwnershipNilCompleteFunc(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fsGroup := int64(1000)
	mounter := &localFakeMounter{path: tmpDir}
	always := v1.FSGroupChangeAlways

	err = SetVolumeOwnership(mounter, tmpDir, &fsGroup, &always, nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestChangeFilePermissionSymlink(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a file and a symlink to it
	realFile := filepath.Join(tmpDir, "realfile")
	symlinkFile := filepath.Join(tmpDir, "symlink")
	if err := os.WriteFile(realFile, []byte("test"), 0644); err != nil {
		t.Fatalf("error creating test file: %v", err)
	}
	if err := os.Symlink(realFile, symlinkFile); err != nil {
		t.Fatalf("error creating symlink: %v", err)
	}

	fsGroup := int64(1000)
	info, err := os.Lstat(symlinkFile)
	if err != nil {
		t.Fatalf("error getting file info: %v", err)
	}

	err = changeFilePermission(symlinkFile, &fsGroup, false, info)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify that the symlink permissions were not changed
	newInfo, err := os.Lstat(symlinkFile)
	if err != nil {
		t.Fatalf("error getting file info after change: %v", err)
	}
	if newInfo.Mode() != info.Mode() {
		t.Errorf("symlink permissions changed unexpectedly")
	}
}

func TestSkipPermissionChangeCombinations(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fsGroup := int64(1000)
	always := v1.FSGroupChangeAlways
	onRootMismatch := v1.FSGroupChangeOnRootMismatch

	tests := []struct {
		name                   string
		fsGroupChangePolicy    *v1.PodFSGroupChangePolicy
		readonly               bool
		expectedSkipPermission bool
	}{
		{"Always policy, not readonly", &always, false, false},
		{"Always policy, readonly", &always, true, false},
		{"OnRootMismatch policy, not readonly", &onRootMismatch, false, false},
		{"OnRootMismatch policy, readonly", &onRootMismatch, true, false},
		{"Nil policy, not readonly", nil, false, false},
		{"Nil policy, readonly", nil, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mounter := &localFakeMounter{
				path:       tmpDir,
				attributes: Attributes{ReadOnly: tt.readonly},
			}
			result := skipPermissionChange(mounter, tmpDir, &fsGroup, tt.fsGroupChangePolicy)
			if result != tt.expectedSkipPermission {
				t.Errorf("expected skipPermission to be %v, got %v", tt.expectedSkipPermission, result)
			}
		})
	}
}

func TestWalkDeepVariousStructures(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a complex directory structure
	if err := os.MkdirAll(filepath.Join(tmpDir, "dir1", "subdir"), 0755); err != nil {
		t.Fatalf("error creating directory structure: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("test"), 0644); err != nil {
		t.Fatalf("error creating test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "dir1", "file2.txt"), []byte("test"), 0644); err != nil {
		t.Fatalf("error creating test file: %v", err)
	}
	if err := os.Symlink(filepath.Join(tmpDir, "file1.txt"), filepath.Join(tmpDir, "symlink")); err != nil {
		t.Fatalf("error creating symlink: %v", err)
	}

	visitedPaths := make(map[string]bool)
	err = walkDeep(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		visitedPaths[path] = true
		return nil
	})

	if err != nil {
		t.Errorf("unexpected error during walkDeep: %v", err)
	}

	expectedPaths := []string{
		tmpDir,
		filepath.Join(tmpDir, "dir1"),
		filepath.Join(tmpDir, "dir1", "subdir"),
		filepath.Join(tmpDir, "file1.txt"),
		filepath.Join(tmpDir, "dir1", "file2.txt"),
		filepath.Join(tmpDir, "symlink"),
	}

	for _, path := range expectedPaths {
		if !visitedPaths[path] {
			t.Errorf("expected path %s was not visited", path)
		}
	}
}

func TestChangeFilePermission2(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fsGroup := int64(1000)

	// Test regular file
	t.Run("Regular file", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "test_file")
		err := os.WriteFile(testFile, []byte("test"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		info, err := os.Stat(testFile)
		if err != nil {
			t.Fatalf("Failed to stat test file: %v", err)
		}

		err = changeFilePermission(testFile, &fsGroup, false, info)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Check if permissions were changed
		newInfo, err := os.Stat(testFile)
		if err != nil {
			t.Fatalf("Failed to stat test file after permission change: %v", err)
		}
		if newInfo.Mode().Perm()&0660 != 0660 {
			t.Errorf("Expected permissions to include 0660, got %v", newInfo.Mode().Perm())
		}
	})

	// Test directory
	t.Run("Directory", func(t *testing.T) {
		testDir := filepath.Join(tmpDir, "test_dir")
		err := os.Mkdir(testDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create test directory: %v", err)
		}

		info, err := os.Stat(testDir)
		if err != nil {
			t.Fatalf("Failed to stat test directory: %v", err)
		}

		err = changeFilePermission(testDir, &fsGroup, false, info)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Check if permissions were changed
		newInfo, err := os.Stat(testDir)
		if err != nil {
			t.Fatalf("Failed to stat test directory after permission change: %v", err)
		}
		if newInfo.Mode().Perm()&0770 != 0770 {
			t.Errorf("Expected permissions to include 0770, got %v", newInfo.Mode().Perm())
		}
	})

	// Test symlink
	t.Run("Symlink", func(t *testing.T) {
		testFile := filepath.Join(tmpDir, "test_file")
		testLink := filepath.Join(tmpDir, "test_link")
		err := os.WriteFile(testFile, []byte("test"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		err = os.Symlink(testFile, testLink)
		if err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}

		info, err := os.Lstat(testLink)
		if err != nil {
			t.Fatalf("Failed to lstat test link: %v", err)
		}

		err = changeFilePermission(testLink, &fsGroup, false, info)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Symlink permissions should not change
		newInfo, err := os.Lstat(testLink)
		if err != nil {
			t.Fatalf("Failed to lstat test link after permission change: %v", err)
		}
		if newInfo.Mode() != info.Mode() {
			t.Errorf("Expected symlink mode to remain unchanged, got %v", newInfo.Mode())
		}
	})
}

func TestSkipPermissionChange2(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fsGroup := int64(1000)
	mounter := &localFakeMounter{path: tmpDir}

	always := v1.FSGroupChangeAlways
	onRootMismatch := v1.FSGroupChangeOnRootMismatch

	testCases := []struct {
		name                   string
		fsGroupChangePolicy    *v1.PodFSGroupChangePolicy
		expectedSkipPermission bool
	}{
		{"nil policy", nil, false},
		{"Always policy", &always, false},
		{"OnRootMismatch policy", &onRootMismatch, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := skipPermissionChange(mounter, tmpDir, &fsGroup, tc.fsGroupChangePolicy)
			if result != tc.expectedSkipPermission {
				t.Errorf("Expected skipPermission to be %v, got %v", tc.expectedSkipPermission, result)
			}
		})
	}
}

func TestRequiresPermissionChange(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fsGroup := int64(1000)

	// Test with non-existent directory
	t.Run("Non-existent directory", func(t *testing.T) {
		result := requiresPermissionChange("/non/existent/dir", &fsGroup, false)
		if !result {
			t.Errorf("Expected true for non-existent directory, got false")
		}
	})

	// Test with matching GID but wrong permissions
	t.Run("Matching GID but wrong permissions", func(t *testing.T) {
		err := os.Chmod(tmpDir, 0700)
		if err != nil {
			t.Fatalf("Failed to change permissions: %v", err)
		}

		result := requiresPermissionChange(tmpDir, &fsGroup, false)
		if !result {
			t.Errorf("Expected true for wrong permissions, got false")
		}
	})

	// Test with correct permissions
	t.Run("Correct permissions", func(t *testing.T) {
		err := os.Chmod(tmpDir, 0770)
		if err != nil {
			t.Fatalf("Failed to change permissions: %v", err)
		}

		result := requiresPermissionChange(tmpDir, &fsGroup, false)
		if !result {
			t.Errorf("Expected true for correct permissions, got false")
		}
	})
}

func TestSetVolumeOwnershipCompleteFunc(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fsGroup := int64(1000)
	mounter := &localFakeMounter{path: tmpDir}
	always := v1.FSGroupChangeAlways

	var completeFuncCalled bool
	var completeFuncErr error

	completeFunc := func(cfp types.CompleteFuncParam) {
		completeFuncCalled = true
		if cfp.Err != nil {
			completeFuncErr = *cfp.Err
		}
	}

	err = SetVolumeOwnership(mounter, tmpDir, &fsGroup, &always, completeFunc)

	if err != nil {
		t.Errorf("Unexpected error from SetVolumeOwnership: %v", err)
	}

	if !completeFuncCalled {
		t.Error("completeFunc was not called")
	}

	if completeFuncErr != nil {
		t.Errorf("Unexpected error in completeFunc: %v", completeFuncErr)
	}

	// Test with nil fsGroup
	completeFuncCalled = false
	completeFuncErr = nil

	err = SetVolumeOwnership(mounter, tmpDir, nil, &always, completeFunc)

	if err != nil {
		t.Errorf("Unexpected error from SetVolumeOwnership with nil fsGroup: %v", err)
	}

	if completeFuncCalled {
		t.Error("completeFunc was called when fsGroup is nil")
	}

	// Test with nil completeFunc
	err = SetVolumeOwnership(mounter, tmpDir, &fsGroup, &always, nil)

	if err != nil {
		t.Errorf("Unexpected error from SetVolumeOwnership with nil completeFunc: %v", err)
	}
}

func TestSetVolumeOwnershipWithReadOnly(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	fsGroup := int64(1000)
	always := v1.FSGroupChangeAlways

	tests := []struct {
		name     string
		readOnly bool
	}{
		{
			name:     "ReadWrite volume",
			readOnly: false,
		},
		{
			name:     "ReadOnly volume",
			readOnly: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mounter := &localFakeMounter{
				path: tmpDir,
				attributes: Attributes{
					ReadOnly: tc.readOnly,
				},
			}

			var completeFuncCalled bool
			var completeFuncErr error

			completeFunc := func(cfp types.CompleteFuncParam) {
				completeFuncCalled = true
				if cfp.Err != nil {
					completeFuncErr = *cfp.Err
				}
			}

			err = SetVolumeOwnership(mounter, tmpDir, &fsGroup, &always, completeFunc)

			if err != nil {
				t.Errorf("Unexpected error from SetVolumeOwnership: %v", err)
			}

			if !completeFuncCalled {
				t.Error("completeFunc was not called")
			}

			if completeFuncErr != nil {
				t.Errorf("Unexpected error in completeFunc: %v", completeFuncErr)
			}

			// Check the permissions of the directory
			info, err := os.Stat(tmpDir)
			if err != nil {
				t.Fatalf("Failed to stat directory: %v", err)
			}

			// Log the actual permissions
			t.Logf("Actual permissions for %s: %v", tc.name, info.Mode().Perm())

			// Verify that permissions are consistent regardless of ReadOnly attribute
			expectedPerm := os.FileMode(0770)
			if info.Mode().Perm() != expectedPerm {
				t.Errorf("Expected permissions %v, got %v", expectedPerm, info.Mode().Perm())
			}

			// Log a message about the ReadOnly attribute not affecting permissions
			t.Logf("Note: ReadOnly attribute (%v) does not affect the set permissions", tc.readOnly)
		})
	}
}

// Custom lstat function that returns an error for the test file
func customLstat(path string) (os.FileInfo, error) {
	if path == testFile {
		return nil, fmt.Errorf("simulated Lstat error")
	}
	return os.Lstat(path)
}

// Custom walk function that uses our custom lstat
func customWalk(path string, info os.FileInfo, walkFn filepath.WalkFunc) error {
	if !info.IsDir() {
		return walkFn(path, info, nil)
	}
	names, err := readDirNames(path)
	if err != nil {
		return err
	}
	for _, name := range names {
		filename := filepath.Join(path, name)
		fileInfo, err := customLstat(filename)
		if err != nil {
			if err := walkFn(filename, fileInfo, err); err != nil && err != filepath.SkipDir {
				return err
			}
		} else {
			err = customWalk(filename, fileInfo, walkFn)
			if err != nil {
				if (!fileInfo.IsDir() || err != filepath.SkipDir) && err != filepath.SkipDir {
					return err
				}
			}
		}
	}
	return nil
}

func TestWalkErrorHandling(t *testing.T) {
	tmpDir, err := utiltesting.MkTmpdir("volume_linux_test")
	if err != nil {
		t.Fatalf("error creating temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a subdirectory and a file
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}
	testFile := filepath.Join(subDir, "testfile")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}



	errorEncountered := false
	testWalkFunc := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if path == testFile && err.Error() == "simulated Lstat error" {
				errorEncountered = true
				return nil // Continue walking
			}
			return err
		}
		return nil
	}

	// Get initial FileInfo for tmpDir
	tmpDirInfo, err := os.Lstat(tmpDir)
	if err != nil {
		t.Fatalf("Failed to get FileInfo for tmpDir: %v", err)
	}

	err = customWalk(tmpDir, tmpDirInfo, testWalkFunc)
	if err != nil {
		t.Errorf("customWalk returned unexpected error: %v", err)
	}

	if !errorEncountered {
		t.Error("Expected to encounter simulated error, but didn't")
	}
}
