package portable

import (
	"errors"
	"fmt"
	"os"
)

var errAlreadyRunning = errors.New("another sec-portable is already using this directory")

// acquireLock holds runtime/portable.lock for the life of the process, so two
// copies never share one SQLite database and rule directory. The operating
// system releases the lock if the process dies.
func acquireLock(path string) (release func(), err error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := lockFile(file); err != nil {
		file.Close()
		return nil, err
	}
	return func() { file.Close() }, nil
}
