package dnsforward

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/AdguardTeam/dnsproxy/proxy"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// DNS cache on-disk format (version 1):
//
//	magic "AGHDNSC1" (8 bytes)
//	section count u32be
//	for each section:
//	  kind u8 (0=general, 1=subnet)
//	  entry count u32be
//	  for each entry:
//	    keyLen u32be + key
//	    valLen u32be + val
//
// Values are the opaque blobs dnsproxy already stores in golibs/cache.  The
// first 4 bytes of each value are the absolute Unix expiration time (see
// dnsproxy's cacheItem.pack).  Expired entries are skipped on load.

const (
	cachePersistMagic   = "AGHDNSC1"
	cachePersistKindGen = 0
	cachePersistKindECS = 1

	defaultCachePersistInterval = 5 * time.Minute
	cachePersistFileName        = "dns_cache.bin"
)

// errCachePersistLayout is returned when dnsproxy/golibs cache internals don't
// match the layout expected by the persistence helpers.
const errCachePersistLayout errors.Error = "unexpected dnsproxy cache layout for persistence"

// cachePersistCtrl owns the optional periodic dump of the DNS cache.
type cachePersistCtrl struct {
	stop chan struct{}
	wg   sync.WaitGroup
}

// startCachePersistLocked starts a background saver when persistence is
// enabled.  s.serverLock must be locked.
func (s *Server) startCachePersistLocked(ctx context.Context) {
	if !s.conf.CachePersistEnabled || !s.conf.CacheEnabled || s.conf.DataDir == "" {
		return
	}

	path := s.cachePersistPath()
	if err := s.loadDNSCache(ctx, path); err != nil {
		s.logger.WarnContext(ctx, "loading persistent dns cache", "path", path, slogutil.KeyError, err)
	}

	interval := time.Duration(s.conf.CachePersistInterval)
	if interval <= 0 {
		interval = defaultCachePersistInterval
	}

	ctrl := &cachePersistCtrl{stop: make(chan struct{})}
	s.cachePersist = ctrl
	ctrl.wg.Add(1)
	go s.cachePersistLoop(ctx, ctrl, path, interval)
}

// stopCachePersistLocked stops the saver and writes a final snapshot.  s.serverLock
// must be locked.
func (s *Server) stopCachePersistLocked(ctx context.Context) {
	ctrl := s.cachePersist
	s.cachePersist = nil
	if ctrl == nil {
		return
	}

	close(ctrl.stop)
	ctrl.wg.Wait()

	if s.dnsProxy == nil || !s.conf.CachePersistEnabled || s.conf.DataDir == "" {
		return
	}

	path := s.cachePersistPath()
	if err := s.saveDNSCache(ctx, path); err != nil {
		s.logger.WarnContext(ctx, "saving persistent dns cache", "path", path, slogutil.KeyError, err)
	}
}

// cachePersistPath returns the on-disk path for the DNS cache blob.
func (s *Server) cachePersistPath() (path string) {
	return filepath.Join(s.conf.DataDir, cachePersistFileName)
}

// cachePersistLoop periodically dumps the live DNS cache.
func (s *Server) cachePersistLoop(
	ctx context.Context,
	ctrl *cachePersistCtrl,
	path string,
	interval time.Duration,
) {
	defer ctrl.wg.Done()

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctrl.stop:
			return
		case <-t.C:
			s.serverLock.RLock()
			p := s.dnsProxy
			enabled := s.conf.CachePersistEnabled
			s.serverLock.RUnlock()
			if !enabled || p == nil {
				continue
			}
			if err := saveProxyDNSCache(path, p); err != nil {
				s.logger.WarnContext(ctx, "periodic dns cache save", "path", path, slogutil.KeyError, err)
			}
		}
	}
}

// loadDNSCache loads a previously saved cache into the live proxy.
func (s *Server) loadDNSCache(ctx context.Context, path string) (err error) {
	if s.dnsProxy == nil {
		return nil
	}

	n, err := loadProxyDNSCache(path, s.dnsProxy)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return err
	}

	s.logger.InfoContext(ctx, "loaded persistent dns cache", "path", path, "entries", n)

	return nil
}

// saveDNSCache writes the live proxy cache to path.
func (s *Server) saveDNSCache(ctx context.Context, path string) (err error) {
	if s.dnsProxy == nil {
		return nil
	}

	n, err := saveProxyDNSCacheCount(path, s.dnsProxy)
	if err != nil {
		return err
	}

	s.logger.InfoContext(ctx, "saved persistent dns cache", "path", path, "entries", n)

	return nil
}

func saveProxyDNSCache(path string, p *proxy.Proxy) (err error) {
	_, err = saveProxyDNSCacheCount(path, p)

	return err
}

// saveProxyDNSCacheCount dumps the proxy cache and returns the entry count.
func saveProxyDNSCacheCount(path string, p *proxy.Proxy) (n int, err error) {
	sections, err := dumpProxyCache(p)
	if err != nil {
		return 0, err
	}

	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, fmt.Errorf("creating cache persist dir: %w", err)
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("creating cache persist temp: %w", err)
	}

	defer func() {
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	if _, err = io.WriteString(f, cachePersistMagic); err != nil {
		return 0, err
	}

	if err = binary.Write(f, binary.BigEndian, uint32(len(sections))); err != nil {
		return 0, err
	}

	for _, sec := range sections {
		if err = binary.Write(f, binary.BigEndian, uint8(sec.kind)); err != nil {
			return 0, err
		}
		if err = binary.Write(f, binary.BigEndian, uint32(len(sec.entries))); err != nil {
			return 0, err
		}
		for _, e := range sec.entries {
			if err = writeBytes(f, e.key); err != nil {
				return 0, err
			}
			if err = writeBytes(f, e.val); err != nil {
				return 0, err
			}
			n++
		}
	}

	if err = f.Sync(); err != nil {
		return 0, err
	}

	if err = os.Rename(tmp, path); err != nil {
		return 0, fmt.Errorf("renaming cache persist file: %w", err)
	}

	return n, nil
}

// loadProxyDNSCache loads entries from path into p and returns how many were
// restored (expired skipped).
func loadProxyDNSCache(path string, p *proxy.Proxy) (n int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	magic := make([]byte, len(cachePersistMagic))
	if _, err = io.ReadFull(f, magic); err != nil {
		return 0, fmt.Errorf("reading magic: %w", err)
	}
	if string(magic) != cachePersistMagic {
		return 0, fmt.Errorf("bad cache persist magic %q", magic)
	}

	var sectionCount uint32
	if err = binary.Read(f, binary.BigEndian, &sectionCount); err != nil {
		return 0, fmt.Errorf("reading section count: %w", err)
	}

	now := uint32(time.Now().Unix())

	for i := uint32(0); i < sectionCount; i++ {
		var kind uint8
		var count uint32
		if err = binary.Read(f, binary.BigEndian, &kind); err != nil {
			return 0, fmt.Errorf("reading section kind: %w", err)
		}
		if err = binary.Read(f, binary.BigEndian, &count); err != nil {
			return 0, fmt.Errorf("reading section count: %w", err)
		}

		var c glcache.Cache
		c, err = proxyCacheByKind(p, kind)
		if err != nil {
			return 0, err
		}

		for j := uint32(0); j < count; j++ {
			var key, val []byte
			key, err = readBytes(f)
			if err != nil {
				return 0, fmt.Errorf("reading key: %w", err)
			}
			val, err = readBytes(f)
			if err != nil {
				return 0, fmt.Errorf("reading value: %w", err)
			}
			if len(val) < 4 {
				continue
			}
			exp := binary.BigEndian.Uint32(val[:4])
			if exp <= now {
				continue
			}
			if c != nil {
				c.Set(key, val)
				n++
			}
		}
	}

	return n, nil
}

type cacheKV struct {
	key []byte
	val []byte
}

type cacheSection struct {
	kind    int
	entries []cacheKV
}

func dumpProxyCache(p *proxy.Proxy) (sections []cacheSection, err error) {
	cacheField := reflect.ValueOf(p).Elem().FieldByName("cache")
	if !cacheField.IsValid() || cacheField.Kind() != reflect.Pointer {
		return nil, errCachePersistLayout
	} else if cacheField.IsNil() {
		return nil, nil
	}

	c := cacheField.Elem()

	general, err := dumpLockedCache(c, "items", "itemsLock")
	if err != nil {
		return nil, err
	}
	subnet, err := dumpLockedCache(c, "itemsWithSubnet", "itemsWithSubnetLock")
	if err != nil {
		return nil, err
	}

	if len(general) > 0 {
		sections = append(sections, cacheSection{kind: cachePersistKindGen, entries: general})
	}
	if len(subnet) > 0 {
		sections = append(sections, cacheSection{kind: cachePersistKindECS, entries: subnet})
	}

	return sections, nil
}

func dumpLockedCache(
	c reflect.Value,
	itemsName string,
	lockName string,
) (entries []cacheKV, err error) {
	items, ok := fieldValue[glcache.Cache](c, itemsName)
	if !ok {
		return nil, errCachePersistLayout
	} else if items == nil {
		return nil, nil
	}

	mu, ok := fieldValue[*sync.RWMutex](c, lockName)
	if !ok || mu == nil {
		return nil, errCachePersistLayout
	}

	mu.Lock()
	defer mu.Unlock()

	return dumpGLCacheItems(items)
}

// dumpGLCacheItems copies all key/value pairs out of a golibs cache.Cache by
// reflecting into its unexported map.  The caller must hold the dnsproxy lock
// that protects this cache.
func dumpGLCacheItems(c glcache.Cache) (entries []cacheKV, err error) {
	v := reflect.ValueOf(c)
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return nil, errCachePersistLayout
	}

	itemsField := v.Elem().FieldByName("items")
	if !itemsField.IsValid() || itemsField.Kind() != reflect.Map {
		return nil, errCachePersistLayout
	}

	for _, mk := range itemsField.MapKeys() {
		it := itemsField.MapIndex(mk)
		if !it.IsValid() || it.IsNil() {
			continue
		}
		item := it.Elem()
		keyField := item.FieldByName("key")
		valField := item.FieldByName("value")
		if !keyField.IsValid() || !valField.IsValid() {
			return nil, errCachePersistLayout
		}
		key := append([]byte(nil), keyField.Bytes()...)
		val := append([]byte(nil), valField.Bytes()...)
		entries = append(entries, cacheKV{key: key, val: val})
	}

	return entries, nil
}

func proxyCacheByKind(p *proxy.Proxy, kind uint8) (c glcache.Cache, err error) {
	cacheField := reflect.ValueOf(p).Elem().FieldByName("cache")
	if !cacheField.IsValid() || cacheField.Kind() != reflect.Pointer || cacheField.IsNil() {
		return nil, errCachePersistLayout
	}

	cVal := cacheField.Elem()
	name := "items"
	if kind == cachePersistKindECS {
		name = "itemsWithSubnet"
	}

	items, ok := fieldValue[glcache.Cache](cVal, name)
	if !ok {
		return nil, errCachePersistLayout
	}

	return items, nil
}

func writeBytes(w io.Writer, b []byte) (err error) {
	if err = binary.Write(w, binary.BigEndian, uint32(len(b))); err != nil {
		return err
	}
	_, err = w.Write(b)

	return err
}

func readBytes(r io.Reader) (b []byte, err error) {
	var n uint32
	if err = binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	b = make([]byte, n)
	_, err = io.ReadFull(r, b)

	return b, err
}

// fieldValue returns the value of the possibly unexported field of the
// addressable struct value v with the given name.  ok is false if there is no
// such field or it has a type other than T.
func fieldValue[T any](v reflect.Value, name string) (val T, ok bool) {
	f := v.FieldByName(name)
	if !f.IsValid() || !f.CanAddr() || f.Type() != reflect.TypeFor[T]() {
		var zero T

		return zero, false
	}

	// #nosec G103 -- The field is addressable and its type has been checked
	// above, so the pointer is valid and of the right type.
	return *(*T)(unsafe.Pointer(f.UnsafeAddr())), true
}
