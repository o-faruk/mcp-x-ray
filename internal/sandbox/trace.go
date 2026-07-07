package sandbox

import (
	"bufio"
	"bytes"
	"regexp"
	"sort"
	"strings"
)

// Observation is what strace saw a target actually do, regardless of
// whether the sandbox's own restrictions (--network none, --read-only)
// caused the attempt to fail — the attempt itself is the signal.
type Observation struct {
	Hosts []string // distinct "ip:port" from connect() calls
	Files []string // distinct paths from open()/openat() calls, outside the expected-noise allowlist
	Execs []string // distinct subprocess paths from execve() calls, excluding the target process's own startup
}

var (
	// Matches an IPv4 connect(); AF_INET6/unix-socket connects aren't
	// parsed for now (see docs/decisions.md follow-ups).
	connectPattern = regexp.MustCompile(`connect\(\d+,\s*\{sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\("([^"]+)"\)`)
	openPattern    = regexp.MustCompile(`open(?:at)?\((?:AT_FDCWD,\s*)?"([^"]+)"`)
	execvePattern  = regexp.MustCompile(`execve\("([^"]+)"`)
)

// boringPathPrefixes are paths every Node/Python process touches just to
// start up — its own interpreter, shared libraries, the target's own
// mounted source — not evidence of anything beyond declared behavior.
var boringPathPrefixes = []string{
	"/usr/",
	"/lib/",
	"/lib64/",
	"/etc/ld.so",
	"/etc/ssl/",
	"/etc/resolv.conf",
	"/etc/hosts",
	"/etc/nsswitch.conf",
	"/etc/localtime",
	"/proc/",
	"/sys/",
	"/dev/",
	"/work",
	"/package.json", // Node's upward module-resolution walk reaching root
	"/tmp/trace.log",
	"/root/.local",
	"/root/.cache",
}

// ParseTrace extracts an Observation from a raw `strace -f -tt` log.
func ParseTrace(log []byte) Observation {
	hosts := make(map[string]bool)
	files := make(map[string]bool)
	execs := make(map[string]bool)
	seenFirstExec := false

	scanner := bufio.NewScanner(bytes.NewReader(log))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		if m := connectPattern.FindStringSubmatch(line); m != nil {
			port, ip := m[1], m[2]
			hosts[ip+":"+port] = true
			continue
		}

		if m := execvePattern.FindStringSubmatch(line); m != nil {
			// The first execve in the whole trace is strace launching the
			// target process itself, not a subprocess the target spawned.
			if !seenFirstExec {
				seenFirstExec = true
				continue
			}
			execs[m[1]] = true
			continue
		}

		if m := openPattern.FindStringSubmatch(line); m != nil {
			path := m[1]
			if !isBoringPath(path) {
				files[path] = true
			}
			continue
		}
	}

	return Observation{
		Hosts: sortedKeys(hosts),
		Files: sortedKeys(files),
		Execs: sortedKeys(execs),
	}
}

func isBoringPath(path string) bool {
	for _, prefix := range boringPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
