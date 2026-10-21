package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/andybalholm/brotli"
)

// IndexHTMLCache 缓存首页 HTML 的原始内容与各编码压缩结果。
//
// 通过“修改时间 + 文件大小”判断 index.html 是否变化：未变化时直接复用缓存，
// 避免每次请求都读盘并重新压缩；变化时重新读取并压缩一次，
// 从而保留“编辑 index.html 后下一次请求即生效”的行为。
// 压缩后的字节只会被整体替换、不会被原地修改，因此可安全地跨请求共享。
type IndexHTMLCache struct {
	// mu 保护以下字段；读多写少，使用读写锁。
	mu sync.RWMutex

	// 缓存对应的文件修改时间与大小，用于判断是否失效；modTime 为零值表示尚未加载。
	modTime time.Time
	size    int64

	// 原始内容与各编码压缩结果。
	raw    []byte
	brotli []byte
	gzip   []byte
}

// fresh 判断缓存是否仍然对应当前的文件信息；调用方必须持有 mu。
func (c *IndexHTMLCache) fresh(info os.FileInfo) bool {
	return !c.modTime.IsZero() && c.modTime.Equal(info.ModTime()) && c.size == info.Size()
}

// pick 返回指定编码对应的响应体；调用方必须持有 mu。
func (c *IndexHTMLCache) pick(compressionType string) []byte {
	switch compressionType {
	case "brotli":
		return c.brotli
	case "gzip":
		return c.gzip
	default:
		return c.raw
	}
}

// body 返回 index.html 在给定编码下的响应体，文件变化时重新加载并压缩。
//
// 参数:
//   - path: index.html 的路径。
//   - compressionType: "brotli"、"gzip"，其它值（含空字符串）表示不压缩。
//   - brotliLevel: brotli 压缩级别。
//   - gzipLevel: gzip 压缩级别。
//
// 返回值:
//   - 对应编码的响应体。
//   - 读取或压缩失败时的错误。
func (c *IndexHTMLCache) body(path, compressionType string, brotliLevel, gzipLevel int) ([]byte, error) {
	// 记录文件信息快照。
	info, statErr := os.Stat(path)
	if statErr != nil {
		return nil, fmt.Errorf("无法读取 HTML 文件信息（入口检查）: %w", statErr)
	}

	// 文件未变化时直接复用缓存。
	c.mu.RLock()
	if c.fresh(info) {
		body := c.pick(compressionType)
		c.mu.RUnlock()
		return body, nil
	}
	c.mu.RUnlock()

	// 文件变化需要重新加载缓存。
	c.mu.Lock()

	// 等待写锁期间文件可能已变化，重新 stat 以基于最新状态判断。
	info, statErr = os.Stat(path)
	if statErr != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("无法读取 HTML 文件信息（锁内二次检查）: %w", statErr)
	}
	if c.fresh(info) {
		body := c.pick(compressionType)
		c.mu.Unlock()
		return body, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("无法读取 HTML 文件: %w", err)
	}
	brotliBody, err := compressBrotli(raw, brotliLevel)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	gzipBody, err := compressGzip(raw, gzipLevel)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}

	c.raw = raw
	c.brotli = brotliBody
	c.gzip = gzipBody
	c.modTime = info.ModTime()
	c.size = info.Size()
	c.mu.Unlock()

	return c.pick(compressionType), nil
}

// compressBrotli 使用给定级别压缩数据，返回 brotli 压缩结果。
func compressBrotli(raw []byte, level int) ([]byte, error) {
	var buf bytes.Buffer

	w := brotli.NewWriterLevel(&buf, level)
	if _, err := w.Write(raw); err != nil {
		return nil, fmt.Errorf("写入 brotli 压缩内容失败: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("关闭 brotli 写入器失败: %w", err)
	}

	return buf.Bytes(), nil
}

// compressGzip 使用给定级别压缩数据，返回 gzip 压缩结果。
func compressGzip(raw []byte, level int) ([]byte, error) {
	var buf bytes.Buffer

	w, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		return nil, fmt.Errorf("创建 Gzip 写入器失败: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return nil, fmt.Errorf("写入 Gzip 压缩内容失败: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("关闭 Gzip 写入器失败: %w", err)
	}

	return buf.Bytes(), nil
}
