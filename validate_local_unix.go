//go:build !windows

package main

import (
	"fmt"
	"path/filepath"
)

// validateLocalName 在非 Windows 平台校验条目能否作为本地文件名使用。
//
// 参数:
//   - name: 去掉前导 "/" 后的条目。
//
// 返回值:
//   - 合法时返回 nil；否则返回说明具体原因的错误。
//
// 说明:
//   - 只依赖 filepath.IsLocal：它在类 Unix 上拦截 ".." 与绝对路径。
//   - 反斜杠在类 Unix 上是合法文件名字符，因此不做限制。
func validateLocalName(name string) error {
	if !filepath.IsLocal(name) {
		return fmt.Errorf("不是合法的本地文件名（可能是绝对路径或含 .. 段）")
	}
	return nil
}
