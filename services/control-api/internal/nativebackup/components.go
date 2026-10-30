package nativebackup

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Host bundles the side effects a component needs, so tests can run every
// step against a temporary root with fake programs.
type Host struct {
	Layout   Layout
	Exec     Executor
	Systemd  Systemd
	Owners   Owners
	Scratch  string // private directory for plaintext staging
	Database DatabaseTarget
}

// DatabaseTarget is the local PostgreSQL cluster the native installer created.
type DatabaseTarget struct {
	Name       string // cdnca
	Owner      string // cdnca
	OSUser     string // postgres (peer authentication)
	ToolsDir   string // directory with pg_dump, pg_restore, psql, pg_dumpall
	RolePrefix string // cdnca
	// Env is passed to every client program (tests point it at a
	// throwaway cluster with PGHOST/PGPORT/PGUSER).
	Env []string
}

func DefaultDatabaseTarget() DatabaseTarget {
	return DatabaseTarget{Name: "cdnca", Owner: "cdnca", OSUser: "postgres", ToolsDir: "/usr/lib/postgresql/17/bin", RolePrefix: "cdnca"}
}

func (target DatabaseTarget) tool(name string) string { return filepath.Join(target.ToolsDir, name) }

// Component captures into and restores from one plaintext tar stream.
type Component interface {
	Name() ComponentName
	Capture(context.Context, *Host, io.Writer) (map[string]string, error)
	// Preflight runs before any restore mutation for every component.
	Preflight(context.Context, *Host, ComponentRecord, Manifest) error
	Restore(context.Context, *Host, ComponentRecord, io.Reader) error
	// Compensate removes what Restore created, leaving the target empty.
	Compensate(context.Context, *Host, ComponentRecord) error
}

func Components() []Component {
	return []Component{
		treeComponent{name: ComponentConfig, paths: configPaths},
		treeComponent{name: ComponentRuntime, paths: runtimePaths},
		postgresComponent{},
		clickhouseComponent{},
		serviceTreeComponent{treeComponent{name: ComponentJetStream, paths: []treePath{{Path: NATSStore, Required: true}}}, "cdnca-control-nats.service"},
		serviceTreeComponent{treeComponent{name: ComponentObjectStore, paths: []treePath{{Path: ObjectStoreData}, {Path: "/var/lib/cdnca-objectstore-logs"}}}, "cdnca-objectstore.service"},
	}
}

// ---- file trees ----

type treeComponent struct {
	name  ComponentName
	paths []treePath
}

func (component treeComponent) Name() ComponentName { return component.name }

func (component treeComponent) Capture(_ context.Context, host *Host, output io.Writer) (map[string]string, error) {
	stats, err := ArchiveTree(host.Layout, component.paths, output)
	if err != nil {
		return nil, err
	}
	return presentDetail(stats), nil
}

func (component treeComponent) Preflight(_ context.Context, host *Host, record ComponentRecord, _ Manifest) error {
	return CheckTreeAbsent(host.Layout, presentPaths(record.Detail))
}

func (component treeComponent) Restore(_ context.Context, host *Host, _ ComponentRecord, input io.Reader) error {
	_, err := ExtractTree(host.Layout, component.paths, host.Owners, input)
	return err
}

func (component treeComponent) Compensate(_ context.Context, host *Host, record ComponentRecord) error {
	return RemoveTrees(host.Layout, presentPaths(record.Detail))
}

// serviceTreeComponent copies a data directory while its single-writer
// service is stopped: a cold, consistent snapshot of every JetStream stream,
// consumer and KV bucket, or of every object version.
type serviceTreeComponent struct {
	treeComponent
	unit string
}

func (component serviceTreeComponent) Capture(ctx context.Context, host *Host, output io.Writer) (detail map[string]string, err error) {
	state, err := host.Systemd.State(ctx, component.unit)
	if err != nil {
		return nil, err
	}
	if state.Active {
		if err := host.Systemd.Stop(ctx, component.unit); err != nil {
			return nil, err
		}
		defer func() {
			if startErr := host.Systemd.Start(context.WithoutCancel(ctx), component.unit); startErr != nil {
				err = errors.Join(err, startErr)
			}
		}()
	}
	return component.treeComponent.Capture(ctx, host, output)
}

func (component serviceTreeComponent) Preflight(ctx context.Context, host *Host, record ComponentRecord, manifest Manifest) error {
	if len(presentPaths(record.Detail)) == 0 {
		return nil
	}
	if state, err := host.Systemd.State(ctx, component.unit); err == nil && state.Active {
		return fmt.Errorf("restore_target_service_running:%s", component.unit)
	}
	return component.treeComponent.Preflight(ctx, host, record, manifest)
}

// ---- PostgreSQL ----

type postgresComponent struct{}

func (postgresComponent) Name() ComponentName { return ComponentPostgreSQL }

var roleNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func (postgresComponent) psql(ctx context.Context, host *Host, database, query string) (string, error) {
	target := host.Database
	return run(ctx, host.Exec, Command{RunAs: target.OSUser, Path: target.tool("psql"),
		Args: []string{"-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "--dbname", database, "--command", query}, Env: target.Env})
}

func (component postgresComponent) Capture(ctx context.Context, host *Host, output io.Writer) (map[string]string, error) {
	target := host.Database
	version, err := component.psql(ctx, host, "postgres", "SHOW server_version_num")
	if err != nil {
		return nil, err
	}
	schema, err := component.psql(ctx, host, target.Name, "SELECT max(version) FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	roles, err := component.psql(ctx, host, "postgres",
		"SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE rolname LIKE '"+target.RolePrefix+"%'")
	if err != nil {
		return nil, err
	}
	var roleList []string
	for _, role := range strings.Split(roles, ",") {
		if !roleNamePattern.MatchString(role) {
			return nil, errors.New("unexpected PostgreSQL role name")
		}
		roleList = append(roleList, role)
	}
	rolesFile := filepath.Join(host.Scratch, "roles.sql")
	dumpFile := filepath.Join(host.Scratch, "database.dump")
	defer os.Remove(rolesFile)
	defer os.Remove(dumpFile)
	var all strings.Builder
	if err := host.Exec.Run(ctx, Command{RunAs: target.OSUser, Path: target.tool("pg_dumpall"),
		Args: []string{"--roles-only"}, Env: target.Env, Stdout: &all}); err != nil {
		return nil, err
	}
	filtered, err := filterRoles(all.String(), roleList)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(rolesFile, []byte(filtered), 0o600); err != nil {
		return nil, err
	}
	// The dump is streamed by the postgres account into a root-owned file.
	dump, err := os.OpenFile(dumpFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	dumpErr := host.Exec.Run(ctx, Command{RunAs: target.OSUser, Path: target.tool("pg_dump"),
		Args: []string{"--format=custom", "--create", "--no-password", "--dbname", target.Name}, Env: target.Env, Stdout: dump})
	closeErr := dump.Close()
	if dumpErr != nil || closeErr != nil {
		return nil, errors.Join(dumpErr, closeErr)
	}
	if err := writeTarFiles(output, map[string]string{"roles.sql": rolesFile, "database.dump": dumpFile}, []string{"roles.sql", "database.dump"}); err != nil {
		return nil, err
	}
	return map[string]string{"server_version_num": version, "database": target.Name, "roles": strings.Join(roleList, ","), "schema_version": schema}, nil
}

// filterRoles keeps only statements about the installation's own roles from
// `pg_dumpall --roles-only`, so the bootstrap superuser is never altered.
func filterRoles(dump string, roles []string) (string, error) {
	allowed := map[string]bool{}
	for _, role := range roles {
		allowed[role] = true
	}
	statement := regexp.MustCompile(`^(CREATE ROLE|ALTER ROLE|GRANT) `)
	var output strings.Builder
	output.WriteString("SET client_min_messages = warning;\n")
	scanner := bufio.NewScanner(strings.NewReader(dump))
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if !statement.MatchString(line) {
			continue
		}
		fields := strings.Fields(line)
		var subject string
		switch fields[0] {
		case "CREATE", "ALTER":
			subject = strings.Trim(strings.TrimSuffix(fields[2], ";"), `"`)
		case "GRANT":
			// GRANT role TO member [WITH ...] [GRANTED BY grantor];
			if len(fields) < 4 {
				continue
			}
			granted := strings.Trim(fields[1], `"`)
			member := strings.Trim(strings.TrimSuffix(fields[3], ";"), `"`)
			if !allowed[granted] || !allowed[member] {
				continue
			}
			line = regexp.MustCompile(` GRANTED BY [^ ;]+`).ReplaceAllString(line, "")
			output.WriteString(line + "\n")
			continue
		}
		if allowed[subject] {
			output.WriteString(line + "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return output.String(), nil
}

func (component postgresComponent) Preflight(ctx context.Context, host *Host, record ComponentRecord, manifest Manifest) error {
	target := host.Database
	version, err := component.psql(ctx, host, "postgres", "SHOW server_version_num")
	if err != nil {
		return fmt.Errorf("restore_postgresql_unavailable: %w", err)
	}
	have, _ := strconv.Atoi(version)
	want, _ := strconv.Atoi(record.Detail["server_version_num"])
	if have/10000 != want/10000 || have < want {
		return fmt.Errorf("restore_postgresql_version_mismatch:%s<%s", version, record.Detail["server_version_num"])
	}
	occupied, err := component.psql(ctx, host, "postgres", "SELECT (SELECT count(*) FROM pg_database WHERE datname = '"+
		target.Name+"') + (SELECT count(*) FROM pg_roles WHERE rolname LIKE '"+target.RolePrefix+"%')")
	if err != nil {
		return err
	}
	if occupied != "0" {
		return errors.New("restore_target_not_empty:postgresql")
	}
	return nil
}

func (component postgresComponent) Restore(ctx context.Context, host *Host, _ ComponentRecord, input io.Reader) error {
	target := host.Database
	files, err := readTarFiles(input, host.Scratch, []string{"roles.sql", "database.dump"})
	if err != nil {
		return err
	}
	defer func() {
		for _, path := range files {
			_ = os.Remove(path)
		}
	}()
	// Both files are fed on stdin: the postgres account cannot traverse the
	// root-private scratch directory, and nothing is made readable to it.
	for _, step := range []struct {
		file string
		path string
		args []string
	}{
		{"roles.sql", target.tool("psql"), []string{"-X", "-q", "-v", "ON_ERROR_STOP=1", "--dbname", "postgres", "--file", "-"}},
		{"database.dump", target.tool("pg_restore"), []string{"--create", "--exit-on-error", "--no-password", "--dbname", "postgres"}},
	} {
		input, err := os.Open(files[step.file])
		if err != nil {
			return err
		}
		runErr := host.Exec.Run(ctx, Command{RunAs: target.OSUser, Path: step.path, Args: step.args, Env: target.Env, Stdin: input})
		_ = input.Close()
		if runErr != nil {
			return runErr
		}
	}
	return nil
}

func (component postgresComponent) Compensate(ctx context.Context, host *Host, record ComponentRecord) error {
	target := host.Database
	var joined error
	if _, err := component.psql(ctx, host, "postgres", "DROP DATABASE IF EXISTS "+target.Name+" WITH (FORCE)"); err != nil {
		joined = err
	}
	roles := strings.Split(record.Detail["roles"], ",")
	for index := len(roles) - 1; index >= 0; index-- {
		if roleNamePattern.MatchString(roles[index]) {
			if _, err := component.psql(ctx, host, "postgres", "DROP ROLE IF EXISTS "+roles[index]); err != nil {
				joined = errors.Join(joined, err)
			}
		}
	}
	return joined
}

// ---- helpers for small multi-file components ----

func writeTarFiles(output io.Writer, files map[string]string, order []string) error {
	writer := tar.NewWriter(output)
	for _, name := range order {
		file, err := os.Open(files[name])
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return err
		}
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: info.Size(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			_ = file.Close()
			return err
		}
		_, err = io.Copy(writer, file)
		_ = file.Close()
		if err != nil {
			return err
		}
	}
	return writer.Close()
}

func readTarFiles(input io.Reader, directory string, want []string) (map[string]string, error) {
	reader := tar.NewReader(input)
	files := map[string]string{}
	allowed := map[string]bool{}
	for _, name := range want {
		allowed[name] = true
	}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || !allowed[header.Name] || files[header.Name] != "" || header.Typeflag != tar.TypeReg {
			return files, ErrArtifactCorrupt
		}
		path := filepath.Join(directory, header.Name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return files, err
		}
		files[header.Name] = path
		written, copyErr := io.Copy(file, reader)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != header.Size {
			return files, ErrArtifactCorrupt
		}
	}
	if len(files) != len(want) {
		return files, ErrArtifactCorrupt
	}
	return files, nil
}
