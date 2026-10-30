package nativeruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// loadTimeout bounds the init-only load: init_by_lua of the node's modules
// takes well under a second; this only stops a hung load.
const loadTimeout = 15 * time.Second

// PrecheckOpenResty checks conf (under prefix, with the -g globals) with the
// binary the runtime link resolves to now: `openresty -t`, then an init-only
// load. `-t` alone never runs Lua (lua-nginx-module returns before creating
// the Lua VM when ngx_test_config is set), so the load is what finds a module
// that does not compile, raises in init_by_lua or is missing: the conf
// without any server{} or init_worker_by_lua*, as one process (master_process
// off) whose pid and log are in a temporary directory. nginx writes the pid
// file after init_by_lua and before it would serve; the precheck then ends
// the process. Nothing listens, no worker starts, nothing running changes.
func PrecheckOpenResty(ctx context.Context, binary, prefix, conf, globals string) error {
	base := []string{"-p", prefix, "-c", conf}
	if output, err := run(ctx, binary, append(base, testArguments(globals)...)...); err != nil {
		return fmt.Errorf("openresty -t: %v: %s", err, output)
	}
	content, err := os.ReadFile(conf)
	if err != nil {
		return err
	}
	stripped, err := stripForInitLoad(content)
	if err != nil {
		return fmt.Errorf("init load of %s: %w", conf, err)
	}
	work, err := os.MkdirTemp("", "cdnca-runtime-load-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	loadConf, pid := filepath.Join(work, "nginx.conf"), filepath.Join(work, "nginx.pid")
	if err := os.WriteFile(loadConf, stripped, 0o600); err != nil {
		return err
	}
	load := fmt.Sprintf("daemon off; master_process off; pid %s; error_log stderr notice;", pid)
	ctx, cancel := context.WithTimeout(ctx, loadTimeout)
	defer cancel()
	var output bytes.Buffer
	command := exec.Command(binary, "-p", prefix, "-c", loadConf, "-g", strings.TrimSpace(globals+" "+load))
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		return fmt.Errorf("openresty init load: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-exited:
			return fmt.Errorf("openresty init load: %v: %s", err, errorText(output.String()))
		case <-ctx.Done():
			_ = command.Process.Kill()
			<-exited
			return fmt.Errorf("openresty init load: %v: %s", ctx.Err(), errorText(output.String()))
		case <-ticker.C:
			if _, err := os.Stat(pid); err == nil {
				_ = command.Process.Kill()
				<-exited
				return nil
			}
		}
	}
}

func testArguments(globals string) []string {
	arguments := []string{"-t", "-q"}
	if globals != "" {
		arguments = append(arguments, "-g", globals)
	}
	return arguments
}

func run(ctx context.Context, binary string, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, arguments...).CombinedOutput()
	return errorText(string(output)), err
}

// initLoadDropped are the main-level directives the load gives with -g
// (nginx refuses a duplicate).
var initLoadDropped = map[string]bool{"pid": true, "daemon": true, "master_process": true, "error_log": true}

// stripForInitLoad is conf without any server{} block (a plain `server x;`
// of an upstream stays), init_worker_by_lua* and the main-level
// initLoadDropped directives. *_by_lua_block bodies are Lua: their braces are
// matched skipping Lua strings and comments.
func stripForInitLoad(conf []byte) ([]byte, error) {
	var output bytes.Buffer
	if end, err := stripBlock(conf, 0, &output, true); err != nil {
		return nil, err
	} else if end != len(conf) {
		return nil, errors.New("unbalanced }")
	}
	return output.Bytes(), nil
}

// stripBlock copies the directives from i up to the } closing the block (or
// the end at main level) and returns the position of that }.
func stripBlock(conf []byte, i int, output *bytes.Buffer, main bool) (int, error) {
	for {
		start := i
		i = skipSpace(conf, i)
		if i >= len(conf) {
			output.Write(conf[start:i])
			if !main {
				return i, errors.New("unexpected end of configuration")
			}
			return i, nil
		}
		if conf[i] == '}' {
			if main {
				return i, errors.New("unbalanced }")
			}
			output.Write(conf[start:i])
			return i, nil
		}
		name := ""
		for first := true; ; first = false {
			i = skipSpace(conf, i)
			if i >= len(conf) {
				return i, errors.New("unterminated directive")
			}
			if conf[i] == ';' || conf[i] == '{' {
				break
			}
			word, next, err := token(conf, i)
			if err != nil {
				return i, err
			}
			if first {
				name = word
			}
			i = next
		}
		drop := name == "server" && conf[i] == '{' || strings.HasPrefix(name, "init_worker_by_lua") ||
			main && initLoadDropped[name]
		if conf[i] == ';' {
			if !drop {
				output.Write(conf[start : i+1])
			}
			i++
			continue
		}
		if strings.HasSuffix(name, "_by_lua_block") {
			end, err := luaBlockEnd(conf, i)
			if err != nil {
				return i, fmt.Errorf("%s: %w", name, err)
			}
			if !drop {
				output.Write(conf[start : end+1])
			}
			i = end + 1
			continue
		}
		var body bytes.Buffer
		end, err := stripBlock(conf, i+1, &body, false)
		if err != nil {
			return end, err
		}
		if !drop {
			output.Write(conf[start : i+1])
			output.Write(body.Bytes())
			output.WriteByte('}')
		}
		i = end + 1
	}
}

// skipSpace skips whitespace and # comments.
func skipSpace(conf []byte, i int) int {
	for i < len(conf) {
		switch conf[i] {
		case ' ', '\t', '\r', '\n':
			i++
		case '#':
			for i < len(conf) && conf[i] != '\n' {
				i++
			}
		default:
			return i
		}
	}
	return i
}

// token reads one quoted or bare argument at i (a bare one stops at
// whitespace, ; and {, except the { of ${var}).
func token(conf []byte, i int) (string, int, error) {
	if quote := conf[i]; quote == '"' || quote == '\'' {
		for j := i + 1; j < len(conf); j++ {
			if conf[j] == '\\' {
				j++
			} else if conf[j] == quote {
				return string(conf[i+1 : j]), j + 1, nil
			}
		}
		return "", i, errors.New("unterminated quoted string")
	}
	j := i
	for ; j < len(conf); j++ {
		c := conf[j]
		if c == '{' && j > i && conf[j-1] == '$' {
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '{' || c == '}' {
			break
		}
	}
	return string(conf[i:j]), j, nil
}

// luaBlockEnd is the position of the } that closes the Lua block opened at
// open, skipping Lua strings, long brackets and comments.
func luaBlockEnd(conf []byte, open int) (int, error) {
	depth := 0
	for i := open; i < len(conf); i++ {
		switch c := conf[i]; {
		case c == '-' && i+1 < len(conf) && conf[i+1] == '-':
			if end, ok := longBracketEnd(conf, i+2); ok {
				i = end
			} else {
				for i < len(conf) && conf[i] != '\n' {
					i++
				}
			}
		case c == '[':
			if end, ok := longBracketEnd(conf, i); ok {
				i = end
			}
		case c == '"' || c == '\'':
			for i++; i < len(conf) && conf[i] != c; i++ {
				if conf[i] == '\\' {
					i++
				}
			}
		case c == '{':
			depth++
		case c == '}':
			if depth--; depth == 0 {
				return i, nil
			}
		}
	}
	return 0, errors.New("unterminated Lua block")
}

// longBracketEnd: at i a Lua long bracket [[ / [==[ starts; the position of
// the last byte of its closing bracket.
func longBracketEnd(conf []byte, i int) (int, bool) {
	if i >= len(conf) || conf[i] != '[' {
		return 0, false
	}
	level := 0
	j := i + 1
	for j < len(conf) && conf[j] == '=' {
		level++
		j++
	}
	if j >= len(conf) || conf[j] != '[' {
		return 0, false
	}
	closing := "]" + strings.Repeat("=", level) + "]"
	end := bytes.Index(conf[j+1:], []byte(closing))
	if end < 0 {
		return len(conf) - 1, true
	}
	return j + 1 + end + len(closing) - 1, true
}

func errorText(text string) string {
	text = strings.TrimSpace(text)
	if len(text) > 2048 {
		text = text[:2048]
	}
	return text
}
