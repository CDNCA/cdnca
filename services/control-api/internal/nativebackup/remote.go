package nativebackup

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Target is one off-host copy destination. Secrets are only read from the
// root-only settings file and are never returned by the HTTP API.
type Target struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // s3 | sftp
	Enabled bool   `json:"enabled"`
	// S3 (AWS, RustFS, MinIO, OSS/COS S3 endpoints)
	Endpoint  string `json:"endpoint,omitempty"`
	Region    string `json:"region,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	PathStyle bool   `json:"path_style,omitempty"`
	AccessKey string `json:"access_key,omitempty"`
	SecretKey string `json:"secret_key,omitempty"`
	// Optional PEM bundle for a private CA (e.g. a self-hosted RustFS).
	CACertificate string `json:"ca_certificate,omitempty"`
	// SFTP
	Host          string `json:"host,omitempty"`
	Port          int    `json:"port,omitempty"`
	Username      string `json:"username,omitempty"`
	RemoteDir     string `json:"remote_dir,omitempty"`
	HostKeySHA256 string `json:"host_key_sha256,omitempty"`
	Password      string `json:"password,omitempty"`
	PrivateKey    string `json:"private_key,omitempty"`
}

var (
	ErrDestinationRefused = errors.New("backup target address is not allowed (loopback, link-local, unspecified or multicast)")
	ErrHostKeyMismatch    = errors.New("SSH host key does not match the pinned fingerprint")
	ErrObjectNotFound     = errors.New("backup object not found")
	targetNamePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	bucketPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionPattern         = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	prefixPattern         = regexp.MustCompile(`^([A-Za-z0-9._-]+/)*$`)
	hostPattern           = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$|^\[?[0-9A-Fa-f:.]+\]?$`)
	usernamePattern       = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	hostKeyPattern        = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
)

// ErrInvalidEndpoint: an S3 endpoint that is not https://host[:port].
var ErrInvalidEndpoint = errors.New("S3 endpoint must be https://host[:port] without a path or query")

func (target Target) Validate() error {
	if !targetNamePattern.MatchString(target.Name) {
		return errors.New("target name must be 1-32 lowercase letters, digits or dashes")
	}
	switch target.Kind {
	case "s3":
		endpoint, err := url.Parse(target.Endpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Path != "" || endpoint.RawQuery != "" ||
			endpoint.Fragment != "" || endpoint.Opaque != "" || endpoint.User != nil {
			return ErrInvalidEndpoint
		}
		if !bucketPattern.MatchString(target.Bucket) || !regionPattern.MatchString(target.Region) ||
			!prefixPattern.MatchString(target.Prefix) || len(target.Prefix) > 255 || target.AccessKey == "" || target.SecretKey == "" {
			return errors.New("S3 target needs an https endpoint, region, bucket, prefix ending in / (or empty) and credentials")
		}
		for _, segment := range strings.Split(strings.TrimSuffix(target.Prefix, "/"), "/") {
			if segment == "." || segment == ".." {
				return errors.New("invalid S3 prefix")
			}
		}
		if target.CACertificate != "" {
			if pool := x509.NewCertPool(); !pool.AppendCertsFromPEM([]byte(target.CACertificate)) {
				return errors.New("invalid CA certificate")
			}
		}
	case "sftp":
		if !hostPattern.MatchString(target.Host) || target.Port < 1 || target.Port > 65535 ||
			!usernamePattern.MatchString(target.Username) || !strings.HasPrefix(target.RemoteDir, "/") ||
			path.Clean(target.RemoteDir) != target.RemoteDir || !hostKeyPattern.MatchString(target.HostKeySHA256) ||
			(target.Password == "") == (target.PrivateKey == "") {
			return errors.New("SFTP target needs host, port, user, absolute directory, pinned host key and exactly one of password or private key")
		}
	default:
		return errors.New("target kind must be s3 or sftp")
	}
	return nil
}

// Redacted returns the target without secrets, with fingerprints instead.
func (target Target) Redacted() map[string]any {
	view := map[string]any{"name": target.Name, "kind": target.Kind, "enabled": target.Enabled}
	if target.Kind == "s3" {
		view["endpoint"], view["region"], view["bucket"], view["prefix"], view["path_style"] = target.Endpoint, target.Region, target.Bucket, target.Prefix, target.PathStyle
		view["access_key_fingerprint"] = secretFingerprint(target.AccessKey)
		view["has_secret_key"] = target.SecretKey != ""
		view["has_ca_certificate"] = target.CACertificate != ""
	} else {
		view["host"], view["port"], view["username"], view["remote_dir"], view["host_key_sha256"] = target.Host, target.Port, target.Username, target.RemoteDir, target.HostKeySHA256
		view["auth"] = "password"
		if target.PrivateKey != "" {
			view["auth"] = "private_key"
		}
	}
	return view
}

func secretFingerprint(secret string) string {
	if secret == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("%x", digest[:4])
}

// Storage is a flat object store keyed by "<backup_id>/<file>".
type Storage interface {
	Put(ctx context.Context, key string, source io.Reader, size int64) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	List(ctx context.Context) ([]string, error) // backup IDs
	DeleteBackup(ctx context.Context, backupID string, files []string) error
	Probe(ctx context.Context) error
	Close() error
}

type dialOptions struct{ allowLoopback bool }

func allowedAddress(address netip.Addr, options dialOptions) bool {
	address = address.Unmap()
	if address.IsLoopback() {
		return options.allowLoopback
	}
	return !(address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() ||
		address.IsMulticast() || address.IsInterfaceLocalMulticast())
}

// guardedDialer resolves names itself so a DNS answer cannot point the root
// agent at the cloud metadata service or another forbidden address.
func guardedDialer(options dialOptions) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		var lastErr error = ErrDestinationRefused
		for _, candidate := range addresses {
			if !allowedAddress(candidate, options) {
				continue
			}
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
			if err == nil {
				return connection, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func OpenStorage(target Target) (Storage, error) { return openStorage(target, dialOptions{}) }

func openStorage(target Target, options dialOptions) (Storage, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if target.Kind == "s3" {
		return newS3Storage(target, options)
	}
	return &sftpStorage{target: target, options: options}, nil
}

type s3Storage struct {
	client *s3.Client
	bucket string
	prefix string
}

func newS3Storage(target Target, options dialOptions) (*s3Storage, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if target.CACertificate != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(target.CACertificate))
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{DialContext: guardedDialer(options), TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
		TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: time.Minute, MaxIdleConns: 4, IdleConnTimeout: time.Minute}
	accessKey, secretKey := target.AccessKey, target.SecretKey
	client := s3.New(s3.Options{Region: target.Region, BaseEndpoint: aws.String(target.Endpoint), UsePathStyle: target.PathStyle,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey, Source: "control-native-backup"}, nil
		}),
		HTTPClient: &http.Client{Transport: transport, Timeout: 6 * time.Hour}, RetryMaxAttempts: 3})
	return &s3Storage{client: client, bucket: target.Bucket, prefix: target.Prefix}, nil
}

func s3NotFound(err error) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		switch apiError.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	return false
}

func (storage *s3Storage) Put(ctx context.Context, key string, source io.Reader, size int64) error {
	if size > 5<<30 {
		return errors.New("单个备份文件超过 5 GiB 单次上传上限，请改用 SFTP 目标")
	}
	_, err := storage.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(storage.bucket), Key: aws.String(storage.prefix + key),
		Body: source, ContentLength: aws.Int64(size), ContentType: aws.String("application/octet-stream")})
	return err
}

func (storage *s3Storage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	object, err := storage.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(storage.bucket), Key: aws.String(storage.prefix + key)})
	if s3NotFound(err) {
		return nil, ErrObjectNotFound
	}
	if err != nil {
		return nil, err
	}
	return object.Body, nil
}

func (storage *s3Storage) List(ctx context.Context) ([]string, error) {
	seen := map[string]bool{}
	paginator := s3.NewListObjectsV2Paginator(storage.client, &s3.ListObjectsV2Input{Bucket: aws.String(storage.bucket),
		Prefix: aws.String(storage.prefix), Delimiter: aws.String("/")})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, common := range page.CommonPrefixes {
			name := strings.TrimSuffix(strings.TrimPrefix(aws.ToString(common.Prefix), storage.prefix), "/")
			if backupIDPattern.MatchString(name) {
				seen[name] = true
			}
		}
	}
	return sortedKeys(seen), nil
}

func (storage *s3Storage) DeleteBackup(ctx context.Context, backupID string, files []string) error {
	var joined error
	for _, file := range files {
		_, err := storage.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(storage.bucket), Key: aws.String(storage.prefix + backupID + "/" + file)})
		if err != nil && !s3NotFound(err) {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func (storage *s3Storage) Probe(ctx context.Context) error {
	key := storage.prefix + ".cdnca-probe-" + NewBackupID(time.Now())
	body := "cdnca control backup probe\n"
	if _, err := storage.client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(storage.bucket), Key: aws.String(key),
		Body: strings.NewReader(body), ContentLength: aws.Int64(int64(len(body)))}); err != nil {
		return fmt.Errorf("写入探测对象失败：%w", err)
	}
	if _, err := storage.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(storage.bucket), Key: aws.String(key)}); err != nil {
		return fmt.Errorf("删除探测对象失败：%w", err)
	}
	return nil
}

func (storage *s3Storage) Close() error { return nil }

// HostKeySHA256 renders a key the way OpenSSH prints it.
func HostKeySHA256(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// DialSSH connects with a pinned host key. Used by SFTP targets and the
// console migration driver.
func DialSSH(ctx context.Context, host string, port int, user string, auth ssh.AuthMethod, pinned string) (*ssh.Client, error) {
	return dialSSH(ctx, host, port, user, auth, pinned, dialOptions{})
}

func dialSSH(ctx context.Context, host string, port int, user string, auth ssh.AuthMethod, pinned string, options dialOptions) (*ssh.Client, error) {
	if !hostPattern.MatchString(host) || port < 1 || port > 65535 || !usernamePattern.MatchString(user) || !hostKeyPattern.MatchString(pinned) {
		return nil, errors.New("invalid SSH destination")
	}
	config := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{auth}, Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if HostKeySHA256(key) != pinned {
				return ErrHostKeyMismatch
			}
			return nil
		}}
	address := net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(port))
	connection, err := guardedDialer(options)(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	conn, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	return ssh.NewClient(conn, channels, requests), nil
}

// FetchHostKey reads a server's host key fingerprint without logging in so
// the operator can compare it out of band before pinning it.
func FetchHostKey(ctx context.Context, host string, port int) (string, error) {
	return fetchHostKey(ctx, host, port, dialOptions{})
}

func fetchHostKey(ctx context.Context, host string, port int, options dialOptions) (string, error) {
	if !hostPattern.MatchString(host) || port < 1 || port > 65535 {
		return "", errors.New("invalid SSH destination")
	}
	var fingerprint string
	seen := errors.New("host key captured")
	config := &ssh.ClientConfig{User: "cdnca-host-key-probe", Timeout: 15 * time.Second,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint = HostKeySHA256(key)
			return seen
		}}
	address := net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprint(port))
	connection, err := guardedDialer(options)(ctx, "tcp", address)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	_, _, _, err = ssh.NewClientConn(connection, address, config)
	if fingerprint != "" {
		return fingerprint, nil
	}
	return "", err
}

func SSHAuth(password, privateKey string) (ssh.AuthMethod, error) {
	if privateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return nil, errors.New("SSH 私钥无法解析（需要未加密的 OpenSSH 私钥）")
		}
		return ssh.PublicKeys(signer), nil
	}
	if password == "" {
		return nil, errors.New("SSH password or private key is required")
	}
	return ssh.Password(password), nil
}

type sftpStorage struct {
	target  Target
	options dialOptions
	ssh     *ssh.Client
	client  *sftp.Client
}

func (storage *sftpStorage) connect(ctx context.Context) (*sftp.Client, error) {
	if storage.client != nil {
		return storage.client, nil
	}
	auth, err := SSHAuth(storage.target.Password, storage.target.PrivateKey)
	if err != nil {
		return nil, err
	}
	client, err := dialSSH(ctx, storage.target.Host, storage.target.Port, storage.target.Username, auth, storage.target.HostKeySHA256, storage.options)
	if err != nil {
		return nil, err
	}
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	storage.ssh, storage.client = client, sftpClient
	return sftpClient, nil
}

func (storage *sftpStorage) path(key string) string { return path.Join(storage.target.RemoteDir, key) }

func (storage *sftpStorage) Put(ctx context.Context, key string, source io.Reader, _ int64) error {
	client, err := storage.connect(ctx)
	if err != nil {
		return err
	}
	destination := storage.path(key)
	if err := client.MkdirAll(path.Dir(destination)); err != nil {
		return err
	}
	temporary := destination + ".part"
	_ = client.Remove(temporary)
	file, err := client.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, source); err != nil {
		_ = file.Close()
		_ = client.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		_ = client.Remove(temporary)
		return err
	}
	if err := client.PosixRename(temporary, destination); err != nil {
		if err := client.Rename(temporary, destination); err != nil {
			_ = client.Remove(temporary)
			return err
		}
	}
	return nil
}

func (storage *sftpStorage) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	client, err := storage.connect(ctx)
	if err != nil {
		return nil, err
	}
	file, err := client.Open(storage.path(key))
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil, ErrObjectNotFound
	}
	return file, err
}

func (storage *sftpStorage) List(ctx context.Context) ([]string, error) {
	client, err := storage.connect(ctx)
	if err != nil {
		return nil, err
	}
	entries, err := client.ReadDir(storage.target.RemoteDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() && backupIDPattern.MatchString(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (storage *sftpStorage) DeleteBackup(ctx context.Context, backupID string, files []string) error {
	client, err := storage.connect(ctx)
	if err != nil {
		return err
	}
	var joined error
	for _, file := range files {
		if err := client.Remove(storage.path(backupID + "/" + file)); err != nil && !errors.Is(err, os.ErrNotExist) {
			joined = errors.Join(joined, err)
		}
	}
	_ = client.RemoveDirectory(storage.path(backupID))
	return joined
}

func (storage *sftpStorage) Probe(ctx context.Context) error {
	client, err := storage.connect(ctx)
	if err != nil {
		return fmt.Errorf("连接失败：%w", err)
	}
	if err := client.MkdirAll(storage.target.RemoteDir); err != nil {
		return fmt.Errorf("无法创建目录 %s：%w", storage.target.RemoteDir, err)
	}
	probe := path.Join(storage.target.RemoteDir, ".cdnca-probe")
	file, err := client.Create(probe)
	if err != nil {
		return fmt.Errorf("写入探测文件失败：%w", err)
	}
	_, err = file.Write([]byte("cdnca control backup probe\n"))
	err = errors.Join(err, file.Close(), client.Remove(probe))
	if err != nil {
		return fmt.Errorf("探测失败：%w", err)
	}
	return nil
}

func (storage *sftpStorage) Close() error {
	if storage.client == nil {
		return nil
	}
	err := errors.Join(storage.client.Close(), storage.ssh.Close())
	storage.client, storage.ssh = nil, nil
	return err
}

// Upload copies a published bundle; the manifest goes last so a remote copy
// without a manifest is recognisably incomplete.
func Upload(ctx context.Context, storage Storage, bundle Bundle) error {
	for _, component := range bundle.Manifest.Components {
		if err := uploadFile(ctx, storage, bundle.Directory, bundle.Manifest.BackupID, component.File); err != nil {
			return fmt.Errorf("upload %s: %w", component.File, err)
		}
	}
	return uploadFile(ctx, storage, bundle.Directory, bundle.Manifest.BackupID, manifestFile)
}

func uploadFile(ctx context.Context, storage Storage, directory, backupID, name string) error {
	file, err := os.Open(filepath.Join(directory, name))
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return storage.Put(ctx, backupID+"/"+name, file, info.Size())
}

// Download fetches a remote bundle into outputDirectory/<backupID> and
// verifies its manifest against the pinned signer before returning.
func Download(ctx context.Context, storage Storage, backupID, outputDirectory, pinnedFingerprint string) (Bundle, error) {
	if !backupIDPattern.MatchString(backupID) {
		return Bundle{}, ErrManifestInvalid
	}
	if err := ensurePrivateDirectory(outputDirectory); err != nil {
		return Bundle{}, err
	}
	directory := filepath.Join(outputDirectory, backupID)
	if err := os.Mkdir(directory, 0o700); err != nil {
		return Bundle{}, err
	}
	fetch := func(name string) error {
		reader, err := storage.Get(ctx, backupID+"/"+name)
		if err != nil {
			return err
		}
		defer reader.Close()
		file, err := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(file, reader)
		return errors.Join(copyErr, file.Sync(), file.Close())
	}
	if err := fetch(manifestFile); err != nil {
		_ = os.RemoveAll(directory)
		return Bundle{}, err
	}
	signed, err := ReadSignedManifest(directory)
	if err != nil {
		_ = os.RemoveAll(directory)
		return Bundle{}, err
	}
	manifest, err := VerifyManifest(signed, pinnedFingerprint)
	if err != nil {
		_ = os.RemoveAll(directory)
		return Bundle{}, err
	}
	for _, component := range manifest.Components {
		if err := fetch(component.File); err != nil {
			_ = os.RemoveAll(directory)
			return Bundle{}, err
		}
	}
	bundle, err := OpenBundle(directory, pinnedFingerprint)
	if err == nil {
		err = bundle.VerifyCiphertext()
	}
	if err != nil {
		_ = os.RemoveAll(directory)
	}
	return bundle, err
}
