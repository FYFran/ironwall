package file

import (
	"os"
	"path/filepath"
)

const uploadDir = "./uploads"

// VULN-3: Path traversal — os.ReadFile with unsanitized path join
func ReadFile(filename string) ([]byte, error) {
	// VULN: filepath.Join does NOT prevent path traversal with ../..
	// ../../etc/passwd resolves correctly outside uploadDir
	path := filepath.Join(uploadDir, filename)
	return os.ReadFile(path)
}
