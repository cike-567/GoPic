package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/valyala/fasthttp"
)

// isAllowed 函数用于检查请求的来源（IP 或域名）是否在白名单中。
//
// 参数:
//   - ctx: *fasthttp.RequestCtx 类型的上下文，包含有关当前请求的信息。
//   - whitelist: *sync.Map 类型的白名单映射，存储被允许访问的 IP 地址和域名。
//
// 返回值:
//   - 返回一个布尔值，表示请求的来源是否被允许，如果来源在白名单中返回 true，
//     否则返回 false。
//
// 说明:
//   - 请求的 Host 可能带端口（RFC 7230 第 5.4 节要求非默认端口写进 Host），
//     白名单条目在装载时已做归一化，因此这里也必须归一化后再比较。
func isAllowed(ctx *fasthttp.RequestCtx, whitelist *sync.Map) bool {
	// 去除端口部分的远程地址（IP）。
	var remoteIP string

	// 标志变量，表示远程 IP 是否在白名单中。
	var ipAllowed bool

	// 标志变量，表示请求的域名是否在白名单中。
	var hostAllowed bool

	// 从请求的上下文中提取客户端的远程 IP。
	remoteIP = ctx.RemoteIP().String()

	// 放行全部 IPv4：白名单包含 "0.0.0.0/0" 时，所有 IPv4 客户端都被允许。
	// 放行全部 IPv6：白名单包含 "::/0" 时，所有 IPv6 客户端都被允许。
	// 按协议族分别判定——IPv4 客户端的地址是点分十进制，IPv6 客户端的地址必含 ":"。
	// 否则只配置其中一个前缀时，另一个协议族也会被一并放行。
	if strings.ContainsRune(remoteIP, ':') {
		// 当前请求来自 IPv6 客户端。
		if _, ipAllowed = whitelist.Load("::/0"); ipAllowed {
			return true
		}
	} else {
		// 当前请求来自 IPv4 客户端。
		if _, ipAllowed = whitelist.Load("0.0.0.0/0"); ipAllowed {
			return true
		}
	}

	// 检查远程 IP 是否在白名单中。
	if _, ipAllowed = whitelist.Load(remoteIP); ipAllowed {
		// 如果远程 IP 在白名单中，打印调试信息并返回 true。
		fmt.Println("ipAllowed")
		return true
	}

	// 检查请求的域名（Host）是否存在于白名单中。
	// ctx.Host() 是 authority（可能带端口、IPv6 带方括号），白名单条目在装载时已归一化，
	// 因此这里必须做同一套归一化，否则带端口的请求永远匹配不上只写主机名的条目。
	if _, hostAllowed = whitelist.Load(normalizeHostPort(string(ctx.Host()))); hostAllowed {
		fmt.Println("hostAllowed")
		return true
	}

	// 如果白名单包含 "*"，表示允许所有域名
	if _, hostAllowed = whitelist.Load("*"); hostAllowed {
		fmt.Println("wildcardAllowed")
		return true
	}

	// 如果远程 IP 或域名都不在白名单中，返回 false，表示请求不被允许。
	return false
}

// authMiddleware 函数是一个中间件，用于根据请求的来源是否在白名单中
// 来控制对后续请求处理程序的访问。
//
// 参数:
//   - next: fasthttp.RequestHandler 类型的处理程序，表示在认证通过后要调用的下一个请求处理程序。
//   - whitelist: *sync.Map 类型的白名单映射，存储被允许访问的请求来源。
//
// 返回值:
//   - 返回一个 fasthttp.RequestHandler 类型的函数，该函数将作为中间件处理每个请求。
func authMiddleware(next fasthttp.RequestHandler, whitelist *sync.Map) fasthttp.RequestHandler {
	// 返回一个新的请求处理函数，用于包裹在中间件逻辑中。
	return func(ctx *fasthttp.RequestCtx) {
		// 检查当前请求的来源是否在白名单中。
		// 使用 isAllowed 函数（假设存在）来判断当前请求 ctx 是否被允许。
		// 如果请求来源不在白名单中，执行重定向操作，将请求重定向到预设的 RedirectURL。
		// 使用 fasthttp.StatusFound 状态码 (302) 指示重定向。
		if !isAllowed(ctx, whitelist) {
			ctx.Redirect(RedirectURL, fasthttp.StatusFound)
			// 结束处理，以防止不在白名单的请求继续执行。
			return
		}
		// 如果请求来源在白名单中，调用下一个处理程序（next）。
		// 传递 ctx 给 next 函数，以允许请求继续执行后续逻辑。
		next(ctx)
	}
}

// populateWhitelist 从给定的白名单字符串中提取主机名，并将其存储到指定的 sync.Map 中。
//
// 参数:
//   - whitelistStr: 以逗号分隔的主机名字符串。
//   - whitelist: 指向存储主机名的 sync.Map 的指针。
//
// 说明:
//   - 每个条目经 normalizeHostPort 归一化后再存储，因此 "example.com" 与
//     "example.com:8080" 等价。
func populateWhitelist(whitelistStr string, whitelist *sync.Map) {
	var (
		// 从白名单字符串中分割出来的主机名切片。
		hosts []string

		// 在遍历时用于暂存每个主机名。
		host string
	)

	// 使用 strings.Split 将白名单按逗号分割为多个主机名，并存储到 hosts 切片中。
	hosts = strings.Split(whitelistStr, ",")

	// 遍历分割后的主机名并存储到 whitelist 中
	for _, host = range hosts {
		// 去除每个主机名前后可能存在的空白字符。
		host = strings.TrimSpace(host)

		// 跳过空条目。
		if host == "" {
			continue
		}

		// 去掉端口、方括号与结尾点后转小写。
		host = normalizeHostPort(host)

		// 将每个主机名存储到 whitelist 中。
		whitelist.Store(host, struct{}{})
	}
}

// normalizeHostPort 把主机名归一化为可用于白名单比较的形式。
//
// 参数:
//   - hostPort: 形如 host、host:port、[v6]、[v6]:port 的字符串。
//
// 返回值:
//   - 去掉端口、方括号与结尾点后的小写主机名，IPv6 保留方括号。
//
// 说明:
//   - 白名单条目与请求的 Host 都经此处理，因此 example.com:8080 这类带端口的条目
//     与任意端口的请求等价。
//   - 端口只认 ":" 后全为数字且非空的部分；无法认定时整串原样返回。
//   - CIDR 与 "*" 令牌不含端口，经过本函数后保持原样。
func normalizeHostPort(hostPort string) string {
	// 统一转小写、去掉首尾空白。
	name := strings.ToLower(strings.TrimSpace(hostPort))

	// 分支 1：方括号包裹的 IPv6 字面量，可能带端口。
	if host, _, found := splitBracketedHostPort(name); strings.HasPrefix(name, "[") && found {
		return host
	}

	// 分支 2：出现多个冒号说明这是未加方括号的 IPv6 字面量。
	if strings.Count(name, ":") > 1 {
		return name
	}

	// 分支 3：只有 ":" 后全为数字时才认定是端口；无法认定时原样返回。
	if host, port, found := strings.Cut(name, ":"); found && isDecimalNumber(port) {
		// 结尾点与不带点的写法等价，去掉；根域名 "." 除外。
		if len(host) > 1 && strings.HasSuffix(host, ".") {
			host = strings.TrimSuffix(host, ".")
		}
		return host
	}

	// 分支 4：走到这里说明没有识别到端口（不含冒号，或冒号后不是数字）。
	// 与分支 3 一致地去掉结尾点，同样保留根域名 "."。
	if len(name) > 1 && strings.HasSuffix(name, ".") {
		name = strings.TrimSuffix(name, ".")
	}
	return name
}

// splitBracketedHostPort 拆出 [v6]:port 的方括号主机部分。
//
// 参数:
//   - name: 已转小写的 authority，以 "[" 开头。
//
// 返回值:
//   - host: 含方括号的 IPv6 主机部分。
//   - port: "]" 之后的端口（不含冒号）；未写出端口时为空。
//   - ok: 是否成功识别出闭合的 "]"；为 false 时前两个返回值无效。
func splitBracketedHostPort(name string) (host string, port string, ok bool) {
	end := strings.IndexByte(name, ']')
	if end < 0 {
		return "", "", false
	}

	// "]" 之后只允许空串或 ":全数字"。
	rest := name[end+1:]
	if rest != "" {
		if !strings.HasPrefix(rest, ":") || !isDecimalNumber(rest[1:]) {
			return "", "", false
		}
		port = rest[1:]
	}
	return name[:end+1], port, true
}

// isDecimalNumber 判断字符串是否非空且全部为 ASCII 数字。
//
// 参数:
//   - s: 待判断的字符串。
//
// 返回值:
//   - 非空且全为 ASCII 数字时返回 true。
func isDecimalNumber(s string) bool {
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
