//go:build unix

package agent

import (
	"fmt"
	"os"
	"syscall"
)

// lockFileName is the advisory lock guarding writes to the state directory.
const lockFileName = ".lock"

// Lock takes an exclusive advisory lock on the state directory and returns the
// function that releases it.
//
// It exists because enrolment is a read-modify-write across two files, and two
// `homeplane-agent enrol` processes (a human and a cron job, a retry and its
// predecessor) can otherwise interleave: both rotate, and the LOSER's older
// credential can land last, leaving the machine holding a credential the server
// has already superseded. The lock serialises the write section; the credential
// -version check in PersistEnrolment is the backstop for the cases a lock
// cannot cover (a filesystem that ignores flock, a process killed mid-write).
func (s *Store) Lock() (func(), error) {
	path := s.dir + string(os.PathSeparator) + lockFileName
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, filePerm)
	if err != nil {
		return nil, fmt.Errorf("open agent state lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock agent state dir %s: %w", s.dir, err)
	}
	return func() {
		// The unlock is implicit in the close, but doing it explicitly keeps the
		// intent legible and releases the lock even if the close fails.
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
