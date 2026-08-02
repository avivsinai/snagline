//go:build darwin || linux || freebsd || openbsd || netbsd

package provision

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// custodySyscalls is the set of post-create steps the tests inject into.
type custodySyscalls struct {
	write   func(*os.File, []byte) (int, error)
	chmod   func(*os.File, os.FileMode) error
	sync    func(*os.File) error
	close   func(*os.File) error
	syncDir func(int) error
}

// realCustodySyscalls returns the production seam values and restores all of
// them when the test ends, so a case that fails part way through cannot leak
// a broken syscall into the tests that follow.
func realCustodySyscalls(t *testing.T) custodySyscalls {
	t.Helper()
	real := custodySyscalls{
		write: writeFile, chmod: chmodFile, sync: syncFile,
		close: closeFile, syncDir: syncDir,
	}
	t.Cleanup(real.restore)
	return real
}

func (c custodySyscalls) restore() {
	writeFile, chmodFile, syncFile = c.write, c.chmod, c.sync
	closeFile, syncDir = c.close, c.syncDir
}

var errInjected = errors.New("injected failure")

// TestWriteToSpendsCustodyAtEveryPostCreateFailurePoint walks every syscall
// that can fail once the key file exists. Creating the file is the point of
// no return: a key artifact has reached the filesystem, so custody is spent
// whatever happens next. Leaving it unspent at any of these points would be
// the worst outcome available — a torn key on disk AND a later WriteTo
// succeeding elsewhere, giving the operator two artifacts for a key that is
// supposed to have exactly one.
func TestWriteToSpendsCustodyAtEveryPostCreateFailurePoint(t *testing.T) {
	for _, testCase := range []struct {
		name string
		// breakStep fails one post-create syscall. It receives the real
		// implementations so a stub can still perform the underlying
		// operation before reporting failure, keeping descriptors honest.
		breakStep func(real custodySyscalls)
	}{
		{
			name: "writing the key bytes fails",
			breakStep: func(custodySyscalls) {
				writeFile = func(*os.File, []byte) (int, error) { return 0, errInjected }
			},
		},
		{
			name: "pinning the file mode fails",
			breakStep: func(custodySyscalls) {
				chmodFile = func(*os.File, os.FileMode) error { return errInjected }
			},
		},
		{
			name: "flushing the file fails",
			breakStep: func(custodySyscalls) {
				syncFile = func(*os.File) error { return errInjected }
			},
		},
		{
			name: "closing the file fails",
			breakStep: func(real custodySyscalls) {
				// Close for real first: reporting a failure without releasing
				// the descriptor would leak it for the rest of the run.
				closeFile = func(file *os.File) error {
					_ = real.close(file)
					return errInjected
				}
			},
		},
		{
			name: "flushing the directory fails",
			breakStep: func(custodySyscalls) {
				syncDir = func(int) error { return errInjected }
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			real := realCustodySyscalls(t)
			testCase.breakStep(real)

			key, err := GenerateSigningKey()
			if err != nil {
				t.Fatal(err)
			}
			dir := custodyTempDir(t)
			first := filepath.Join(dir, "first.pem")
			if err := key.WriteTo(first); err == nil {
				t.Fatal("WriteTo reported success despite a failed post-create step")
			}
			if _, err := os.Lstat(first); err != nil {
				t.Fatalf("WriteTo did not retain the partial key artifact: %v", err)
			}

			// Restore every seam so the follow-up write would otherwise
			// succeed. Without this a still-broken syscall would fail the
			// second write on its own and mask an unspent custody.
			real.restore()

			second := filepath.Join(dir, "second.pem")
			if err := key.WriteTo(second); err == nil {
				t.Fatal("a failed write left custody unspent: a later WriteTo to a different path succeeded")
			}
			if _, err := os.Lstat(second); err == nil {
				t.Fatal("the refused later write still created a file")
			}
		})
	}
}

// TestWriteToKeepsCustodySpentWhenPostCreateFailureLeavesItsArtifact proves
// that a partial artifact is retained rather than unsafely unlinked by name.
func TestWriteToKeepsCustodySpentWhenPostCreateFailureLeavesItsArtifact(t *testing.T) {
	real := realCustodySyscalls(t)
	syncFile = func(*os.File) error { return errInjected }

	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := custodyTempDir(t)
	first := filepath.Join(dir, "first.pem")
	if err := key.WriteTo(first); err == nil {
		t.Fatal("WriteTo reported success despite a failed post-create step")
	}
	if _, err := os.Lstat(first); err != nil {
		t.Fatalf("expected retained partial key artifact, got: %v", err)
	}

	real.restore()

	second := filepath.Join(dir, "second.pem")
	if err := key.WriteTo(second); err == nil {
		t.Fatal("a failed write un-spent custody: a later WriteTo produced a second key artifact")
	}
	if _, err := os.Lstat(second); err == nil {
		t.Fatal("the refused later write still created a file")
	}
}

// TestWriteToPerformsCustodyStepsInOrder pins the sequence, not just the set.
// Each step depends on the one before it: the mode must be pinned before the
// flush that makes the file durable, the contents must be flushed before the
// file is closed, and the directory entry is flushed last because there is no
// point publishing an entry for contents that are not yet on stable storage.
func TestWriteToPerformsCustodyStepsInOrder(t *testing.T) {
	real := realCustodySyscalls(t)

	var steps []string
	// Every seam delegates to the real syscall, so this also proves the
	// genuine durability path runs clean rather than merely being reached.
	writeFile = func(file *os.File, data []byte) (int, error) {
		steps = append(steps, "write")
		return real.write(file, data)
	}
	chmodFile = func(file *os.File, mode os.FileMode) error {
		steps = append(steps, "chmod")
		return real.chmod(file, mode)
	}
	syncFile = func(file *os.File) error {
		steps = append(steps, "sync-file")
		return real.sync(file)
	}
	closeFile = func(file *os.File) error {
		steps = append(steps, "close")
		return real.close(file)
	}
	syncDir = func(dirFD int) error {
		steps = append(steps, "sync-dir")
		return real.syncDir(dirFD)
	}

	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(custodyTempDir(t), "signing.pem")
	if err := key.WriteTo(path); err != nil {
		t.Fatal(err)
	}

	want := []string{"write", "chmod", "sync-file", "close", "sync-dir"}
	if !reflect.DeepEqual(steps, want) {
		t.Fatalf("custody steps ran as %v, want exactly %v", steps, want)
	}
	if _, err := LoadSigningKey(path); err != nil {
		t.Fatalf("the key written through the ordered path did not load back: %v", err)
	}
}

// TestWriteToFailsWhenTheNamedParentChanges proves a retained directory FD
// cannot turn a renamed parent into a successful write at a different path.
func TestWriteToFailsWhenTheNamedParentChanges(t *testing.T) {
	real := realCustodySyscalls(t)

	base := custodyTempDir(t)
	keyDir := filepath.Join(base, "keys")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	movedDir := filepath.Join(base, "moved")

	// The file flush is the last step before the directory flush, making this
	// the latest possible moment to invalidate the pathname.
	syncFile = func(file *os.File) error {
		if err := os.Rename(keyDir, movedDir); err != nil {
			t.Errorf("could not rename the key directory mid-write: %v", err)
		}
		return real.sync(file)
	}

	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := key.WriteTo(filepath.Join(keyDir, "signing.pem")); err == nil {
		t.Fatal("WriteTo succeeded after its named parent directory was renamed")
	}
	if _, err := LoadSigningKey(filepath.Join(keyDir, "signing.pem")); err == nil {
		t.Fatal("WriteTo reported failure but left a usable key at the original name")
	}
	if _, err := os.Lstat(filepath.Join(movedDir, "signing.pem")); err != nil {
		t.Fatalf("expected the spent key artifact to remain under the moved directory: %v", err)
	}
}

// TestWriteToFailsWhenTheNamedLeafChanges proves final validation rejects a
// same-parent leaf replacement made after durability is flushed.
func TestWriteToFailsWhenTheNamedLeafChanges(t *testing.T) {
	real := realCustodySyscalls(t)
	dir := custodyTempDir(t)
	path := filepath.Join(dir, "signing.pem")
	replacementPath := filepath.Join(dir, "replacement.pem")
	replacement := []byte("not our key")
	syncDir = func(dirFD int) error {
		if err := real.syncDir(dirFD); err != nil {
			return err
		}
		if err := os.WriteFile(replacementPath, replacement, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacementPath, path); err != nil {
			t.Fatal(err)
		}
		return nil
	}

	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := key.WriteTo(path); err == nil {
		t.Fatal("WriteTo succeeded after its named leaf was replaced")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("final validation removed the concurrent replacement: %v", err)
	}
	if !reflect.DeepEqual(got, replacement) {
		t.Fatalf("replacement contents = %q, want %q", got, replacement)
	}
}

// TestWriteToLeavesAConcurrentReplacement proves failed writes never perform
// a path-based cleanup that could delete a same-name replacement.
func TestWriteToLeavesAConcurrentReplacement(t *testing.T) {
	real := realCustodySyscalls(t)
	dir := custodyTempDir(t)
	path := filepath.Join(dir, "signing.pem")
	replacement := []byte("not our key")
	syncFile = func(file *os.File) error {
		if err := real.sync(file); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, replacement, 0o600); err != nil {
			t.Fatal(err)
		}
		return errInjected
	}

	key, err := GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := key.WriteTo(path); err == nil {
		t.Fatal("WriteTo reported success after an injected post-create failure")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed write removed the concurrent replacement: %v", err)
	}
	if !reflect.DeepEqual(got, replacement) {
		t.Fatalf("replacement contents = %q, want %q", got, replacement)
	}
}
