package pollinate

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/letsencrypt/cactus/log/tilewriter"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// Response size caps. A full hash tile is 8 KiB; a checkpoint with a
// few ML-DSA-44 signature lines is a handful of KiB. Entry bundles hold
// up to 256 entries of up to 64 KiB each, so their cap is the framing
// maximum.
const (
	maxCheckpointBytes  = 1 << 20
	maxHashTileBytes    = tilewriter.EntriesPerDataTile * tlogx.HashSize
	maxEntryBundleBytes = tilewriter.EntriesPerDataTile * (2 + 0xffff)
)

// errNotFound reports a 404 from a source, so callers can distinguish
// "this resource does not exist there" from transport failures.
var errNotFound = errors.New("pollinate: not found")

// counter is the minimal metric surface tiles.go needs; nil is inert.
type counter interface{ Add(float64) }

// tileCache is a bounded LRU of *verified* tile bytes, shared across
// all sources and keyed by origin plus tile path. Tiles are immutable
// for a given path, and only tiles that tlog.TileHashReader has
// authenticated against a checkpoint root are saved, so a cache hit is
// as trustworthy as a fresh fetch and considerably cheaper for whoever
// we would have fetched from.
type tileCache struct {
	mu    sync.Mutex
	max   int
	items map[string]*list.Element
	order *list.List // front = most recently used
}

type tileCacheItem struct {
	key  string
	data []byte
}

func newTileCache(maxTiles int) *tileCache {
	return &tileCache{
		max:   maxTiles,
		items: make(map[string]*list.Element),
		order: list.New(),
	}
}

func (c *tileCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*tileCacheItem).data, true
}

func (c *tileCache) put(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)
		el.Value.(*tileCacheItem).data = data
		return
	}
	c.items[key] = c.order.PushFront(&tileCacheItem{key: key, data: data})
	for len(c.items) > c.max {
		el := c.order.Back()
		c.order.Remove(el)
		delete(c.items, el.Value.(*tileCacheItem).key)
	}
}

// tileFetcher reads one log from one source (a CA's log prefix URL or a
// mirror's <monitoring prefix>/<origin hash> prefix) over the
// c2sp.org/tlog-tiles interface. It implements tlog.TileReader, so
// tlog.TileHashReader can serve authenticated stored hashes from it.
type tileFetcher struct {
	ctx    context.Context
	base   string // log prefix URL, no trailing slash
	origin string
	hc     *http.Client
	cache  *tileCache
	reads  counter // HTTP GETs against this source
}

func (f *tileFetcher) get(url string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(f.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if f.reads != nil {
		f.reads.Add(1)
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pollinate: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", errNotFound, url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pollinate: GET %s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pollinate: read %s: %w", url, err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("pollinate: %s exceeds %d bytes", url, maxBytes)
	}
	return body, nil
}

// checkpoint fetches and parses the source's current checkpoint.
func (f *tileFetcher) checkpoint() (*Note, error) {
	body, err := f.get(f.base+"/checkpoint", maxCheckpointBytes)
	if err != nil {
		return nil, err
	}
	return ParseNote(body)
}

// Height implements tlog.TileReader.
func (f *tileFetcher) Height() int { return tilewriter.TileHeight }

// ReadTiles implements tlog.TileReader: it serves hash tiles from the
// verified cache when possible and fetches the rest over HTTP. A
// partial tile that the source no longer stores (because its tree has
// since grown past it) is recovered from the full tile, of which the
// partial is a byte prefix.
func (f *tileFetcher) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		path := tilewriter.TilePath(t)
		if data, ok := f.cache.get(f.origin + "/" + path); ok {
			out[i] = data
			continue
		}
		data, err := f.get(f.base+"/"+path, maxHashTileBytes)
		if errors.Is(err, errNotFound) && t.W != 1<<uint(t.H) {
			full := t
			full.W = 1 << uint(t.H)
			data, err = f.get(f.base+"/"+tilewriter.TilePath(full), maxHashTileBytes)
			if err == nil {
				if len(data) < t.W*tlogx.HashSize {
					return nil, fmt.Errorf("pollinate: tile %s is %d bytes, want at least %d",
						tilewriter.TilePath(full), len(data), t.W*tlogx.HashSize)
				}
				data = data[:t.W*tlogx.HashSize]
			}
		}
		if err != nil {
			return nil, err
		}
		out[i] = data
	}
	return out, nil
}

// SaveTiles implements tlog.TileReader. tlog.TileHashReader only calls
// it for tiles it has authenticated against the tree root, which is
// what makes them safe to share via the cache.
func (f *tileFetcher) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	for i, t := range tiles {
		if len(data[i]) == 0 {
			continue
		}
		f.cache.put(f.origin+"/"+tilewriter.TilePath(t), data[i])
	}
}

// entryBundle fetches the entry bundle at index tileN and returns its
// first want entries. Like ReadTiles, it falls back from a partial
// bundle path to the full bundle when the source's tree has grown past
// the width we derived from our checkpoint.
func (f *tileFetcher) entryBundle(tileN int64, want int) ([][]byte, error) {
	data, err := f.get(f.base+"/"+tilewriter.DataTilePath(tileN, want), maxEntryBundleBytes)
	if errors.Is(err, errNotFound) && want != tilewriter.EntriesPerDataTile {
		data, err = f.get(f.base+"/"+tilewriter.DataTilePath(tileN, tilewriter.EntriesPerDataTile), maxEntryBundleBytes)
	}
	if err != nil {
		return nil, err
	}
	entries, err := tilewriter.SplitDataTile(data)
	if err != nil {
		return nil, fmt.Errorf("pollinate: entry bundle %d: %w", tileN, err)
	}
	if len(entries) < want {
		return nil, fmt.Errorf("pollinate: entry bundle %d has %d entries, want %d", tileN, len(entries), want)
	}
	return entries[:want], nil
}

// trimSlash normalises a configured URL prefix.
func trimSlash(u string) string { return strings.TrimSuffix(u, "/") }
