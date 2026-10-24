package check

import "strconv"

// credNames are the files the home-directory credential listing looks for,
// each its own -name branch: the catalog admits no glob and no parenthesis
// (docs/spec/host-collector.md §3, G5).
var credNames = []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ed25519_sk", "id_ecdsa_sk",
	"credentials", "credentials.db", "application_default_credentials.json", "access_tokens.db"}

// envNames are the .env files an application folder is searched for, by
// exact name for the same reason; templates (.env.example) are left out.
var envNames = []string{".env", ".env.local", ".env.production", ".env.production.local", ".env.prod",
	".env.staging", ".env.development", ".env.development.local"}

// findPruned is the start of a find over roots that stays on one device, is
// depth-capped and does not enter the pruned names.
func findPruned(roots, prune []string) []string {
	argv := append([]string{"find"}, roots...)
	argv = append(argv, "-xdev", "-maxdepth", "4")
	for _, n := range prune {
		argv = append(argv, "-name", n, "-prune", "-o")
	}
	// Folders that stop group or others getting in are listed; a folder is
	// listed before its contents, so a listed file always has the folders
	// above it listed too.
	return append(argv, "-type", "d", "-not", "-perm", "-0011", "-ls")
}

// CredFindArgv is find over the home-directory roots, listing the folders
// that block others and the private-key and cloud-credential files by name
// (names, modes and owners only: never contents).
func CredFindArgv(roots, prune []string) []string {
	argv := findPruned(roots, prune)
	for _, n := range credNames {
		argv = append(argv, "-o", "-type", "f", "-name", n, "-ls", "-o", "-type", "l", "-name", n, "-ls")
	}
	return argv
}

// AppEnvSlots is how many application folders a host may declare; each has
// its own catalog slot, because a fact is keyed by check id.
const AppEnvSlots = 5

// AppEnvID is the check id of the n-th (1-based) application folder's slot.
func AppEnvID(n int) string { return "creds.app_env_" + strconv.Itoa(n) }

// EnvFindArgv is the same walk over one application folder, listing .env
// files; the folder is the check's path parameter.
func EnvFindArgv() []string {
	argv := findPruned([]string{"{path}"}, []string{"node_modules", ".git", "vendor", ".venv"})
	for _, n := range envNames {
		argv = append(argv, "-o", "-type", "f", "-name", n, "-ls", "-o", "-type", "l", "-name", n, "-ls")
	}
	return argv
}
