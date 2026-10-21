package main

import "strings"

// encodingPreference 表示 Accept-Encoding 中的一个编码 token 及其 q 值。
//
// q 用于排序与排除：0 表示客户端显式拒绝该编码（RFC 9110 第 12.5.3 节），
// 缺省值为 1。token 统一转为小写比较，因为编码名的大小写不敏感。
type encodingPreference struct {
	name string
	q    float64
}

// parseAcceptEncoding 解析 Accept-Encoding 请求头，返回各编码 token 及其 q 值。
//
// 参数:
//   - header: 请求头中的原始 Accept-Encoding 值，可能为空。
//
// 返回值:
//   - 按头部出现顺序排列的编码偏好列表，其中的 name 可能是通配符 "*"；
//     空元素会被跳过。
//
// 说明:
//   - 没有 q 参数的 token 按缺省值 1 处理；只有 q 参数存在但值非法时才按 0 处理。
//   - 非法 q 值按 0 处理：宁可不压缩，也不发送客户端可能拒绝的编码。
func parseAcceptEncoding(header string) []encodingPreference {
	var prefs []encodingPreference

	for _, element := range strings.Split(header, ",") {
		name, q, qFound := parseEncodingElement(element)
		if name == "" {
			continue
		}
		// 存在 q 参数时用解析出的值，否则用缺省值 1。
		if !qFound {
			q = 1
		}
		prefs = append(prefs, encodingPreference{name: name, q: q})
	}
	return prefs
}

// parseEncodingElement 解析 Accept-Encoding 的单个元素，如 "br;q=0.8"。
//
// 参数:
//   - element: 逗号分隔后的单个元素。
//
// 返回值:
//   - name: 小写的编码名或通配符 "*"；元素为空时为""。
//   - q: 该编码的 q 值；非法 q 值按 0 处理。
//   - qFound: 元素中是否存在 q 参数。不存在时 q 取规范缺省值 1，而不是 0。
func parseEncodingElement(element string) (name string, q float64, qFound bool) {
	element = strings.TrimSpace(element)

	// 元素形如 token *(";" 参数)，参数名与 token 之间只以分号分隔，
	// 因此必须先按分号切分再判断参数名：直接在原串上查找 "q=" 会把
	// "foo;qq=0" 之类的参数误认为 q 参数。
	i := strings.IndexByte(element, ';')
	if i < 0 {
		return strings.ToLower(element), 1, false
	}

	name = strings.ToLower(strings.TrimSpace(element[:i]))
	for _, param := range strings.Split(element[i+1:], ";") {
		key, value, found := strings.Cut(param, "=")
		if !found || !strings.EqualFold(strings.TrimSpace(key), "q") {
			continue
		}
		// 非法 q 值按 0 处理：宁可不压缩，也不发送客户端可能拒绝的编码。
		return name, parseQualityValue(value), true
	}

	// 没有 q 参数时按 q=1 处理。
	return name, 1, false
}

// parseQualityValue 解析 q 参数的值，按 RFC 9110 的 qvalue 格式处理。
//
// 参数:
//   - value: "q=" 之后的原始值，可能带空白。
//
// 返回值:
//   - 合法 q 值；非法值一律返回 0。
//
// 说明:
//   - 规范允许最多三位小数（如 "0.5"、"0.125"），因此不使用 strconv.ParseFloat：
//     否则 "0.5.5" 之类超出 qvalue 语法的值会被当成有效值接受。
func parseQualityValue(value string) float64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}

	// 小数点前后必须是纯数字；"1" 等价于 "1.0"（整数形式的 q 没有小数部分）。
	whole, frac := value, ""
	if i := strings.IndexByte(value, '.'); i >= 0 {
		whole, frac = value[:i], value[i+1:]
	}
	if !isDecimalDigits(whole) || (frac != "" && !isDecimalDigits(frac)) {
		return 0
	}

	// 小数部分最多三位，多余位数按非法 q 值处理。
	if len(frac) > 3 {
		return 0
	}

	q := float64(whole[0] - '0')
	for i := 1; i < len(whole); i++ {
		q = q*10 + float64(whole[i]-'0')
	}
	if frac != "" {
		q += float64(frac[0]-'0') / 10
		if len(frac) > 1 {
			q += float64(frac[1]-'0') / 100
		}
		if len(frac) > 2 {
			q += float64(frac[2]-'0') / 1000
		}
	}

	// q 的合法区间是 [0,1]，越界值按非法处理。
	if q < 0 || q > 1 {
		return 0
	}
	return q
}

// isDecimalDigits 判断字符串是否非空且全部为 ASCII 数字。
//
// 参数:
//   - s: 待判断的字符串。
//
// 返回值:
//   - 非空且全为 ASCII 数字时返回 true。
func isDecimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// negotiateCompression 按客户端偏好与服务器能力选择响应的压缩方式。
//
// 参数:
//   - prefs: parseAcceptEncoding 解析出的偏好列表。
//   - compressionEnabled: 是否启用压缩；为 false 时不压缩。
//
// 返回值:
//   - "brotli"、"gzip" 或 ""（不压缩）。
//
// 说明:
//   - q 值高者优先；q 相同时优先 brotli，因为浏览器通常不会给 br 更高的 q，
//     而 brotli 对 HTML 的压缩率高于 gzip。
//   - 通配符 * 只在客户端没有显式列出该编码时生效。
//   - 没有任何可接受编码时返回空字符串，调用方据此返回未压缩响应；
//     收窄响应集（406）不在本函数职责内。
func negotiateCompression(prefs []encodingPreference, compressionEnabled bool) string {
	if !compressionEnabled {
		return ""
	}

	// 以 -1 起手：q=0 表示显式拒绝，不能与「该编码未出现」混为一谈。
	bestName, bestQ := "", -1.0

	for _, supported := range []string{"br", "gzip"} {
		// 通配符只在客户端没有显式列出该编码时生效（RFC 9110 第 12.5.3 节）。
		q, ok := explicitQuality(prefs, supported)
		if !ok {
			q, ok = explicitQuality(prefs, "*")
		}
		if !ok || q <= 0 {
			continue
		}

		if q > bestQ || (q == bestQ && supported == "br") {
			bestName, bestQ = supported, q
		}
	}

	return wireName(bestName)
}

// explicitQuality 返回指定 token 在偏好列表中的 q 值。
//
// 参数:
//   - prefs: parseAcceptEncoding 解析出的偏好列表。
//   - name: 待查询的编码 token，已转为小写。
//
// 返回值:
//   - q: 该 token 的 q 值；未出现时无意义。
//   - ok: 该 token 是否出现在偏好列表中；未出现时为 false。
//
// 说明:
//   - 同一个 token 出现多次时取最大值。
func explicitQuality(prefs []encodingPreference, name string) (q float64, ok bool) {
	for _, p := range prefs {
		if p.name != name {
			continue
		}
		if !ok || p.q > q {
			q, ok = p.q, true
		}
	}
	return q, ok
}

// wireName 把内部编码名映射为下游处理器使用的压缩类型名。
//
// 参数:
//   - supported: 内部编码名，取值 "br" 或 "gzip"。
//
// 返回值:
//   - handlers.go 使用的压缩类型名；未知编码返回空字符串，表示不压缩。
func wireName(supported string) string {
	switch supported {
	case "br":
		return "brotli"
	case "gzip":
		return "gzip"
	default:
		return ""
	}
}
