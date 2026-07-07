package sandbox_test

import (
	"reflect"
	"testing"

	"github.com/ofaruk/mcp-x-ray/internal/sandbox"
)

const sampleTrace = `12345 14:23:01.100000 execve("/usr/local/bin/node", ["node", "server.js"], 0x7fff /* 8 vars */) = 0
12345 14:23:01.101000 openat(AT_FDCWD, "/usr/local/lib/node_modules/foo.js", O_RDONLY) = 3
12345 14:23:01.102000 openat(AT_FDCWD, "/work/server.js", O_RDONLY) = 4
12345 14:23:01.103000 openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = -1 EACCES (Permission denied)
12345 14:23:01.104000 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.7")}, 16) = -1 ENETUNREACH (Network is unreachable)
12345 14:23:01.105000 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.51.100.7")}, 16) = -1 ENETUNREACH (Network is unreachable)
12346 14:23:01.106000 execve("/bin/sh", ["/bin/sh", "-c", "id"], 0x7fff /* 8 vars */) = 0
`

func TestParseTrace(t *testing.T) {
	obs := sandbox.ParseTrace([]byte(sampleTrace))

	if !reflect.DeepEqual(obs.Hosts, []string{"198.51.100.7:443"}) {
		t.Errorf("Hosts = %+v, want [198.51.100.7:443]", obs.Hosts)
	}
	if !reflect.DeepEqual(obs.Files, []string{"/root/.ssh/id_rsa"}) {
		t.Errorf("Files = %+v, want [/root/.ssh/id_rsa] (boring paths and /work filtered out)", obs.Files)
	}
	if !reflect.DeepEqual(obs.Execs, []string{"/bin/sh"}) {
		t.Errorf("Execs = %+v, want [/bin/sh] (the initial node execve excluded)", obs.Execs)
	}
}

func TestParseTrace_Empty(t *testing.T) {
	obs := sandbox.ParseTrace([]byte(""))
	if len(obs.Hosts) != 0 || len(obs.Files) != 0 || len(obs.Execs) != 0 {
		t.Errorf("expected empty observation, got %+v", obs)
	}
}
