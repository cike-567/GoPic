//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// windowsIllegalNameChars 是 Windows 上无法出现在文件名中的字符。
//
// 说明:
//   - 反斜杠在此单独列出：它既是路径分隔符，也无法作为文件名字符。
//   - * | < > " 在 Windows 上创建即失败，filepath.IsLocal 不会拦截它们。
const windowsIllegalNameChars = "*|<>\"\\"

// validateLocalName 在 Windows 上校验条目能否作为本地文件名使用。
//
// 参数:
//   - name: 去掉前导 "/" 后的条目。
//
// 返回值:
//   - 合法时返回 nil；否则返回说明具体原因的错误。
//
// 说明:
//   - 先用 filepath.IsLocal 拦截保留设备名（NUL、CON、COM1）、盘符与 ADS（a:b.png）、
//     ".." 与绝对路径；再补充 IsLocal 不覆盖的 Windows 非法文件名字符。
func validateLocalName(name string) error {
	if strings.ContainsAny(name, windowsIllegalNameChars) {
		return fmt.Errorf("包含 Windows 文件名不允许的字符")
	}
	if !filepath.IsLocal(name) {
		return fmt.Errorf("不是合法的本地文件名（可能是保留设备名、盘符或绝对路径）")
	}
	return nil
}
