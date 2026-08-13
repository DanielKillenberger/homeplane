//go:build !unix

package agent

// Lock is a no-op on platforms Homeplane does not support (the installer
// rejects them outright). The credential-version check in PersistEnrolment
// still prevents a superseded credential from being persisted, so the file
// exists to keep the package compilable rather than to provide a guarantee.
func (s *Store) Lock() (func(), error) {
	return func() {}, nil
}
