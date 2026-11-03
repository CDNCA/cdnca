package dyncache

// Exact purge of chunked objects (ADR 0021 section 8): on a chunking node a
// large object is stored as chunks, one file per chunk:
//   <key>|slice=bytes=<i*C>-<(i+1)*C-1>[|e=<chunk generation>]
// Their files are found by path (md5 of the key), never by a zone scan: the
// node's cache module forgets the object's chunk state and returns it (total
// length, chunk generation), and every chunk file of the generations a
// request can still reach ("" and the current one) is removed. Without a
// known length the first chunks are probed and the length is read from a
// chunk's Content-Range.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
)

// ChunkForgetPath is the cache module's control endpoint.
const ChunkForgetPath = "/cache/chunks/forget"

const (
	// chunkProbe: chunks looked for when the length is not known (the first
	// 64 chunks: 256 MiB of 4 MiB chunks).
	chunkProbe = 64
	// chunkSlack: chunks past the known length also removed (a longer
	// earlier version of the object).
	chunkSlack = 4
	// maxChunks bounds one object (64 GiB of 4 MiB chunks).
	maxChunks = 16384
)

// chunkState is one object's chunk state as the cache module had it.
type chunkState struct {
	Epoch int64  `json:"epoch"`
	Total int64  `json:"total"`
	Kind  string `json:"kind"` // "c" chunks, "w" whole object, "" unknown
}

// forgetChunks asks the cache module to forget the objects' chunk state.
func forgetChunks(ctx context.Context, control Control, keys []string) (map[string]chunkState, error) {
	body, _ := json.Marshal(map[string]any{"keys": keys})
	raw, err := control.Post(ctx, ChunkForgetPath, body)
	if err != nil {
		return nil, err
	}
	var answer struct {
		States map[string]chunkState `json:"states"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("%w: chunk forget answer", ErrInvalid)
	}
	return answer.States, nil
}

// chunkKey is the key of chunk index of an object (edgecache.ChunkVariants:
// <key>|slice=$slice_range$cdnca_chunk_epoch).
func chunkKey(key string, chunkBytes int64, index int64, epoch int64) string {
	value := key + "|slice=bytes=" + strconv.FormatInt(index*chunkBytes, 10) + "-" + strconv.FormatInt((index+1)*chunkBytes-1, 10)
	if epoch > 0 {
		value += "|e=" + strconv.FormatInt(epoch, 10)
	}
	return value
}

// removeKey removes the file of key when it is that key's (errNeedScan
// for a file the fast path cannot vouch for).
func removeKey(dir, key string, result *Result) (bool, error) {
	path := FilePath(dir, key)
	raw, info, err := readKey(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || raw != key {
		return false, errNeedScan
	}
	parsed, _ := ParseKey(raw)
	entry := entryOf(path, parsed, info)
	removed, err := remove(entry)
	if err != nil {
		return false, err
	}
	if removed {
		result.Affected++
		result.Bytes += entry.Size
	}
	return true, nil
}

// purgeChunks removes every chunk file of one object (key: its whole
// object key) of the generations "" and state.Epoch. found: some file of
// the object was there (whole object or chunk).
func purgeChunks(ctx context.Context, dir, key string, chunkBytes int64, state chunkState, result *Result) (bool, error) {
	found := false
	for _, epoch := range uniqueEpochs(state.Epoch) {
		count := int64(0)
		if state.Total > 0 {
			count = (state.Total+chunkBytes-1)/chunkBytes + chunkSlack
		}
		probing := count == 0
		if probing {
			count = chunkProbe
		}
		for index := int64(0); index < count && index < maxChunks; index++ {
			if ctx.Err() != nil {
				return found, ctx.Err()
			}
			chunk := chunkKey(key, chunkBytes, index, epoch)
			if probing {
				// the length of the object, from the first chunk found
				if total, ok := chunkTotal(FilePath(dir, chunk), chunk); ok {
					count, probing = (total+chunkBytes-1)/chunkBytes+chunkSlack, false
				}
			}
			removed, err := removeKey(dir, chunk, result)
			if err != nil {
				return found, err
			}
			found = found || removed
		}
	}
	return found, nil
}

func uniqueEpochs(epoch int64) []int64 {
	if epoch > 0 {
		return []int64{0, epoch}
	}
	return []int64{0}
}

// chunkTotal reads the complete length of a cached chunk's Content-Range
// (the stored upstream response header after the KEY line).
func chunkTotal(path, key string) (int64, bool) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, false
	}
	defer file.Close()
	header, err := io.ReadAll(io.LimitReader(file, headerLimit))
	if err != nil {
		return 0, false
	}
	start := bytes.Index(header, []byte("\nKEY: "+key+"\n"))
	if start < 0 {
		return 0, false
	}
	scanner := bufio.NewScanner(bytes.NewReader(header[start+len(key)+7:]))
	for scanner.Scan() {
		line := bytes.TrimRight(scanner.Bytes(), "\r")
		if len(line) == 0 {
			break
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || !bytes.EqualFold(bytes.TrimSpace(name), []byte("Content-Range")) {
			continue
		}
		_, total, ok := bytes.Cut(bytes.TrimSpace(value), []byte("/"))
		if !ok {
			return 0, false
		}
		number, err := strconv.ParseInt(string(total), 10, 64)
		return number, err == nil && number > 0
	}
	return 0, false
}
