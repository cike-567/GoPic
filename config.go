package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/valyala/fasthttp"
	"golang.org/x/sync/semaphore"
)

// 定义 ServerConfig 结构体，用于存储服务器配置。
type ServerConfig struct {
	// 图片 URL 清单。
	ImagesUrls []string

	// 图片 URL 的类型，决定如何处理图片 URL。
	IsNetworkPath bool

	// 图片数据缓存。
	ImagesCache *ristretto.Cache

	// 缓存过期时间，单位为秒。
	CacheExpireSeconds int

	// 是否启用压缩
	EnableCompression bool

	// 预加载时要写入缓存的预热类型，元素取自 brotli、gzip、raw。
	// 与 EnableCompression 相互独立：后者只控制响应压缩，前者只控制启动时预热什么。
	PreloadTypes []string

	// Brotli 压缩级别
	// BestSpeed (值为 0)：最快的压缩速度，压缩率较低。
	// BestCompression (值为 11)：最佳压缩率，但压缩速度较慢。
	// DefaultCompression (值为 6)：默认的压缩级别，适用于大多数情况下的折中选择。
	BrotliLevel int

	// Gzip 压缩级别
	// CompressNoCompression (值为 0)：无压缩，数据直接传输，适用于不希望压缩数据的情况。
	// CompressBestSpeed (值为 1)：最快的压缩速度，但压缩率较低。
	// CompressBestCompression (值为 9)：最佳压缩率，但压缩速度较慢。
	// CompressDefaultCompression (值为 -1)：默认的压缩级别，通常在速度和压缩率之间取得平衡。
	// CompressHuffmanOnly
	GzipLevel int

	// HTTP 服务的端口号。
	Port string

	// index.html 文件的路径。
	IndexHtmlPath string

	// 首页 HTML 缓存（原始内容与各编码产物）。
	IndexHTMLCache *IndexHTMLCache

	// 域名和 IP 白名单。
	Whitelist sync.Map

	// 控制并发量的信号量。
	Sem *semaphore.Weighted
}

// 硬编码的 URL 常量
const (
	RedirectURL = "https://http.cat/599"
)

// 压缩级别的默认值与合法范围。
// gzip: HuffmanOnly(-2) 到 BestCompression(9)，对应标准库 compress/flate 的常量。
// brotli: 0 到 11，对应 github.com/andybalholm/brotli 的 minQuality/maxQuality。
const (
	DefaultGzipLevel   = -1
	MinGzipLevel       = -2
	MaxGzipLevel       = 9
	DefaultBrotliLevel = 6
	MinBrotliLevel     = 0
	MaxBrotliLevel     = 11
)

// 预热类型：决定 PRELOAD_IMAGES 为 true 时把哪些数据写入缓存。
// 取值与图片缓存键的编码位一致，raw 对应原图（编码位为空字符串）。
const (
	PreloadTypeBrotli = "brotli"
	PreloadTypeGzip   = "gzip"
	PreloadTypeRaw    = "raw"

	// EnvPreloadTypes 是决定预热内容的环境变量名。
	EnvPreloadTypes = "PRELOAD_TYPES"

	// DefaultPreloadTypes 是未配置 EnvPreloadTypes 时使用的默认预热类型。
	DefaultPreloadTypes = PreloadTypeBrotli

	// PreloadTypeSeparator 分隔多个预热类型，与 WHITELIST 的分隔约定一致。
	PreloadTypeSeparator = ","
)

// 配置来源的说明文本，用于错误信息。
const (
	// SourceEnvFile 表示配置来自运行目录下的 .env 文件。
	SourceEnvFile = ".env"

	// SourceSystemEnv 表示配置来自系统环境变量。
	SourceSystemEnv = "系统环境变量"
)

// requiredKeys 是必须显式配置的键，任一项缺失、为空或取值非法都会终止启动。
// 未列入的键（PRELOAD_TYPES、GZIP_LEVEL、BROTLI_LEVEL）属可选项：
// 未配置或显式留空时使用各自的默认值。
var requiredKeys = []string{
	"BASE_URL",
	"CSV_PATH",
	"IMAGE_URL_TYPE",
	"PORT",
	"PRELOAD_IMAGES",
	"ENABLE_COMPRESSION",
	"INDEX_HTML_PATH",
	"WHITELIST",
}

// optionalKeys 是允许留空并取默认值的键，仅在系统环境变量来源下用于装载配置。
var optionalKeys = []string{
	EnvPreloadTypes,
	"GZIP_LEVEL",
	"BROTLI_LEVEL",
}

// 出站抓取与并发等待的超时，避免对端挂起时请求无限期占用资源。
const (
	// 单次网络图片抓取的总时限，同时作为读/写超时上限。
	imageFetchTimeout = 5 * time.Second

	// 网络响应体上限（含成功、错误和重定向响应）；等于上限允许。
	maxImageResponseBytes = 4 << 20

	// 等待并发信号量的最长时间，超时返回 503。
	semaphoreWaitTimeout = 5 * time.Second
)

// serverReadTimeout 服务端读取整个请求（含请求头与请求体）的最长时间。
const serverReadTimeout = 5 * time.Second

// serverWriteTimeout 服务端向客户端写出响应（含刷出写缓冲）的单次最长时间。
const serverWriteTimeout = 10 * time.Second

// maxConnsPerIP 单个 IP 允许同时保持的连接数上限，超过时新连接收到 429 并立即关闭。
const maxConnsPerIP = 100

// indexHTMLMaxAge 首页 HTML 允许被浏览器缓存的最长时间。
const indexHTMLMaxAge = 5 * time.Minute

// imageHTTPClient 用于抓取网络路径的图片。
//
// 说明:
//   - SecureErrorLogMessage 只能在派生 HostClient 时设置：Client 本身没有该字段，
//     必须通过 ConfigureClient 钩子写入。否则 fasthttp 会把响应头解析失败的
//     buffer 内容（即上游发回的原始字节）格式化进 error，经 RandomImageHandler
//     打印到标准输出。服务端已设置该选项（见 server.go），出站方向与此对齐。
var imageHTTPClient = &fasthttp.Client{
	MaxResponseBodySize:       maxImageResponseBytes,
	ReadTimeout:               imageFetchTimeout,
	WriteTimeout:              imageFetchTimeout,
	MaxIdemponentCallAttempts: 1,
	ConfigureClient: func(hc *fasthttp.HostClient) error {
		hc.SecureErrorLogMessage = true
		return nil
	},
}

// loadEnvFile 从指定的 .env 文件中加载环境变量并返回一个键值对映射。
//
// 参数:
//   - filename: .env 文件的路径。
//
// 返回值:
//   - 一个包含环境变量的字典。
//   - 可能发生的错误信息。
//
// 说明:
//   - 每行在读入时即去除首尾空白，因此空行、顶格注释与缩进注释行为一致。
//   - 行尾注释不受支持：值中的 "#" 会被当作值的一部分保留。
//   - 文件不使用 defer 关闭：打开后的出口只有无效行分支与函数末尾两处，均显式关闭；
//     新增提前返回时必须同步补上 file.Close()。
func loadEnvFile(filename string) (map[string]string, error) {
	var (
		// 存储从 .env 文件读取的环境变量的字典。
		envVars map[string]string = make(map[string]string)

		// 储存打开的 .env 文件。
		file *os.File

		// 储存可能发生的错误的信息。
		err error

		// 用于逐行扫描 .env 文件内容的扫描器。
		scanner *bufio.Scanner

		// 当前读取的行文本内容。
		line string

		// 拆分后的键值对。
		parts []string

		// 环境变量的键。
		key string

		// 环境变量的值。
		value string
	)

	// 打开指定的 .env 文件。
	file, err = os.Open(filename)
	// 如果打开文件失败，将返回一个错误。
	if err != nil {
		return nil, fmt.Errorf("打开 .env 文件失败: %w", err)
	}
	// 创建一个新的扫描器，用于逐行读取文件内容。
	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		// 读取当前行并去掉首尾空白。
		line = strings.TrimSpace(scanner.Text())

		// 跳过空行和以 # 开头的注释行。
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 使用 '=' 分隔符将行拆分为键和值。
		// SplitN 函数确保最多拆分为两个部分。
		parts = strings.SplitN(line, "=", 2)
		// 如果行没有被正确拆分为键值对，则显式关闭文件后返回错误。
		if len(parts) != 2 {
			// 忽略关闭失败的返回信息。
			_ = file.Close()
			return nil, fmt.Errorf("在 .env 文件中存在无效行: %s", line)
		}

		// 去除键和值的前后空白字符。
		key = strings.TrimSpace(parts[0])
		value = strings.TrimSpace(parts[1])

		//	将键值对存储到 envVars 中。
		envVars[key] = value
	}

	// 忽略关闭失败的返回信息。
	_ = file.Close()

	// 返回解析后的环境变量和可能发生的错误的信息。
	return envVars, scanner.Err()
}

// loadConfigMap 按来源装载配置，返回键值映射与来源说明。
//
// 返回值:
//   - envVars: 配置键值对。未配置的键不会出现在映射中，以保留「缺失」语义。
//   - source: 来源说明，用于错误信息。
//
// 说明:
//   - 运行目录下存在 .env 时只读取该文件；存在但解析失败会终止启动。
//   - 不存在 .env 时读取系统环境变量，未设置的环境变量不写入映射。
//   - 两条来源返回同一种映射形状，后续校验与读取逻辑因此完全共用。
func loadConfigMap() (map[string]string, string) {
	// 检查运行目录下是否存在 .env 文件。
	if _, statErr := os.Stat("./.env"); statErr == nil {
		envVars, err := loadEnvFile("./.env")
		if err != nil {
			panic(fmt.Sprintf("加载 .env 文件失败: %v\n", err))
		}
		return envVars, SourceEnvFile
	} else if !os.IsNotExist(statErr) {
		// 无法确定 .env 文件是否存在，直接终止启动。
		panic(fmt.Sprintf("检查 .env 文件失败: %v\n", statErr))
	}

	// 不存在 .env 文件，从系统环境变量中装载配置。
	envVars := make(map[string]string)
	for _, key := range append(append([]string{}, requiredKeys...), optionalKeys...) {
		if value, exists := os.LookupEnv(key); exists {
			envVars[key] = value
		}
	}
	return envVars, SourceSystemEnv
}

// requireKeys 校验必需键是否全部存在于配置中，缺失任一项都会终止启动。
//
// 参数:
//   - envVars: 已装载的配置键值对。
//   - keys: 必须存在的键。
//   - source: 配置来源说明，用于错误信息。
//
// 说明:
//   - 一次性列出全部缺失键，避免用户修好一项后再次撞上下一项。
//   - 只判断键是否存在；键存在但内容非法由各自的校验负责。
func requireKeys(envVars map[string]string, keys []string, source string) {
	var missing []string
	for _, key := range keys {
		if _, exists := envVars[key]; !exists {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		panic(fmt.Sprintf("配置错误: %s 缺少必需配置项: %s；这些键必须显式写出",
			source, strings.Join(missing, ", ")))
	}
}

// requireNonEmpty 校验指定键的值非空白，空白时终止启动。
//
// 参数:
//   - envVars: 已装载的配置键值对。
//   - key: 待校验的键。
//   - source: 配置来源说明，用于错误信息。
//
// 说明:
//   - 写成 "KEY=" 属于显式留空，不套用默认值，视为配置错误。
//   - 仅用 TrimSpace 判断是否空白，不改写映射中的值。
func requireNonEmpty(envVars map[string]string, key, source string) {
	if strings.TrimSpace(envVars[key]) == "" {
		panic(fmt.Sprintf("配置错误: %s 中的 %s 为空；该键必须显式填写，不会套用默认值",
			source, key))
	}
}

// mustParseBool 校验布尔配置项，只接受 "true" 与 "false"。
//
// 参数:
//   - raw: 配置中的原始字符串。
//   - name: 配置项的名称，用于错误提示。
//   - source: 配置来源说明，用于错误信息。
//
// 返回值:
//   - 解析后的布尔值。
//
// 说明:
//   - 非法取值终止启动：静默按 false 处理会让实际行为与配置不符。
func mustParseBool(raw, name, source string) bool {
	switch raw {
	case "true":
		return true
	case "false":
		return false
	default:
		panic(fmt.Sprintf("配置错误: %s 中的 %s 取值非法: %q；合法取值为 true 或 false",
			source, name, raw))
	}
}

// mustParsePort 校验端口配置，必须是 1 到 65535 的无符号十进制数。
//
// 参数:
//   - raw: 配置中的原始字符串。
//   - name: 配置项的名称，用于错误提示。
//   - source: 配置来源说明，用于错误信息。
//
// 返回值:
//   - 校验通过的端口字符串，原样返回。
//
// 说明:
//   - 不接受正负号与空白，因此不复用允许符号的 isSignedDecimal。
//   - 逐字符累加求值，不依赖 strconv；先按长度拦截超长输入，累加不会溢出。
func mustParsePort(raw, name, source string) string {
	if raw == "" {
		panic(fmt.Sprintf("配置错误: %s 中的 %s 不是合法端口: %q；必须是 1 到 65535 的整数",
			source, name, raw))
	}

	// 65535 最多 5 位，更长的输入必然越界；先按长度拦截，避免累加时溢出回绕。
	if len(raw) > 5 {
		panic(fmt.Sprintf("配置错误: %s 中的 %s 超出合法范围 [1, 65535]: %q",
			source, name, raw))
	}

	port := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			panic(fmt.Sprintf("配置错误: %s 中的 %s 不是合法端口: %q；必须是 1 到 65535 的整数",
				source, name, raw))
		}
		port = port*10 + int(raw[i]-'0')
	}

	if port < 1 || port > 65535 {
		panic(fmt.Sprintf("配置错误: %s 中的 %s 超出合法范围 [1, 65535]: %q",
			source, name, raw))
	}
	return raw
}

// mustParseImageURLType 校验 IMAGE_URL_TYPE，只接受 localpath 与 networkpath。
//
// 参数:
//   - raw: 配置中的原始字符串。
//   - source: 配置来源说明，用于错误信息。
//
// 返回值:
//   - 是否为网络路径。
//
// 说明:
//   - 非法取值终止启动：静默按 localpath 处理会让图片源指向错误。
func mustParseImageURLType(raw, source string) bool {
	switch raw {
	case "localpath":
		return false
	case "networkpath":
		return true
	default:
		panic(fmt.Sprintf("配置错误: %s 中的 IMAGE_URL_TYPE 取值非法: %q；合法取值为 localpath 或 networkpath",
			source, raw))
	}
}

// validateBaseURL 校验 BASE_URL 的形式，返回不合法的原因。
//
// 参数:
//   - raw: 配置中的原始字符串。
//   - isNetworkPath: 是否为网络路径，决定采用哪套规则。
//
// 返回值:
//   - 合法时返回 nil；否则返回说明具体原因的错误。
func validateBaseURL(raw string, isNetworkPath bool) error {
	if raw == "" {
		return fmt.Errorf("不能为空")
	}

	if isNetworkPath {
		return validateNetworkBaseURL(raw)
	}
	return validateLocalBaseURL(raw)
}

// validateNetworkBaseURL 校验网络模式的 BASE_URL。
//
// 参数:
//   - raw: 配置中的原始字符串。
//
// 返回值:
//   - 合法时返回 nil；否则返回说明具体原因的错误。
//
// 说明:
//   - scheme 只允许 http 与 https：fasthttp 不支持其它协议，
//     在这里拦下比等到抓取图片时报 "unsupported protocol" 更容易定位。
//   - authority 不允许含 userinfo：fasthttp 不会把 userinfo 转成 Authorization，
//     该写法既无法认证，又会让凭据随图片清单进入启动日志。
func validateNetworkBaseURL(raw string) error {
	// 控制字符与空白会让比较路径与实际请求不一致。
	for i := 0; i < len(raw); {
		r, size, ok := decodeUTF8Rune(raw[i:])
		if !ok {
			return fmt.Errorf("包含非法的 UTF-8 字节序列")
		}
		if isUnicodeSpace(r) || isUnicodeControl(r) {
			return fmt.Errorf("包含空白或控制字符")
		}
		i += size
	}

	if strings.ContainsAny(raw, "?#\\") {
		return fmt.Errorf("包含 ?、# 或反斜杠；这些字符会让基础 URL 与实际请求不一致")
	}

	end := urlAuthorityEnd(raw)
	if end < 0 {
		return fmt.Errorf("缺少 scheme://authority 结构，形如 https://cdn.example.com/img")
	}

	schemeEnd := strings.Index(raw, "://")
	scheme := strings.ToLower(raw[:schemeEnd])
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("scheme %q 不受支持；只支持 http 与 https", raw[:schemeEnd])
	}

	authority := raw[schemeEnd+3 : end]
	if authority == "" {
		return fmt.Errorf("authority 为空，形如 https://cdn.example.com/img")
	}

	if strings.ContainsRune(authority, '@') {
		return fmt.Errorf("authority 含 userinfo；该写法不会被用于认证，且会把凭据写入启动日志")
	}

	// hasEncodedTraversal 面向不含前导 "/" 的单条路径，这里必须逐段校验：
	// 否则路径自身的 "/" 会被它当成解码出的分隔符而误报。
	for _, segment := range strings.Split(raw[end:], "/") {
		if hasEncodedTraversal(segment) {
			return fmt.Errorf("路径包含可能改变层级的百分号编码")
		}
	}

	if hasDotDotSegment(raw[end:]) {
		return fmt.Errorf("路径包含 . 或 .. 段")
	}

	return nil
}

// validateLocalBaseURL 校验本地模式的 BASE_URL：目录必须存在且确实是目录。
//
// 参数:
//   - raw: 配置中的原始字符串。
//
// 返回值:
//   - 合法时返回 nil；否则返回说明具体原因的错误。
//
// 说明:
//   - 允许 "./images" 这类含 "." 段的写法，只拒绝上溯的 ".." 段。
//   - 不拒绝目录名中的空格：本地目录名含空格是合法用法。
func validateLocalBaseURL(raw string) error {
	for _, segment := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if segment == ".." {
			return fmt.Errorf("路径包含 .. 段")
		}
	}

	// 根目录与裸盘符必须拒绝：readLines 会把条目归一为以 "/" 开头，
	// 与这类 BASE_URL 拼接会得到 "//x" 或 "C:/x" 这种形态，
	// 在 Windows 上会被 Clean 成 UNC 路径或落到盘符根，脱离原目录语义。
	clean := filepath.Clean(raw)
	if strings.HasSuffix(clean, string(filepath.Separator)) {
		return fmt.Errorf("是根目录或以路径分隔符结尾；请指定具体的图片目录")
	}
	if volume := filepath.VolumeName(clean); volume != "" && clean == volume+"." {
		return fmt.Errorf("只指定了盘符 %q，未指定目录", volume)
	}

	info, err := os.Stat(raw)
	if err != nil {
		return fmt.Errorf("无法访问该目录: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("该路径不是目录")
	}

	return nil
}

// hasDotDotSegment 判断路径是否含 "." 或 ".." 段。
//
// 参数:
//   - p: URL 的路径部分。
//
// 返回值:
//   - 含 "." 或 ".." 段时返回 true。
//
// 说明:
//   - 按 "/" 字面切分，不解码百分号编码；编码形式由 hasEncodedTraversal 负责。
func hasDotDotSegment(p string) bool {
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// mustValidateBaseURL 校验 BASE_URL，非法取值终止启动。
//
// 参数:
//   - raw: 配置中的原始字符串。
//   - source: 配置来源说明，用于错误信息。
//   - isNetworkPath: 是否为网络路径。
//
// 返回值:
//   - 校验通过的 BASE_URL，原样返回。
//
// 说明:
//   - 非法取值终止启动：静默继续会在装载阶段把全部条目判为越界，
//     最终表现为 /random-image 恒返回 503，而错误信息不指向配置本身。
func mustValidateBaseURL(raw, source string, isNetworkPath bool) string {
	if err := validateBaseURL(raw, isNetworkPath); err != nil {
		panic(fmt.Sprintf("配置错误: %s 中的 BASE_URL 非法: %v", source, err))
	}
	return raw
}

// whitelistEntryCount 统计白名单中实际装载的条目数。
//
// 参数:
//   - whitelist: 已装载的白名单映射。
//
// 返回值:
//   - 条目数；0 表示没有任何条目，所有请求都会被重定向。
func whitelistEntryCount(whitelist *sync.Map) int {
	var count int
	whitelist.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// mustPopulateWhitelist 装载白名单，并在装载结果为空时终止启动。
//
// 参数:
//   - raw: 白名单的原始配置值。
//   - source: 配置来源说明，用于错误信息（".env" 或 "系统环境变量"）。
//
// 返回值:
//   - 已装载的白名单映射；空白名单不返回，直接终止启动。
//
// 说明:
//   - 空白名单属于配置错误，立刻失败。
//   - 显式空值与只有逗号的写法都归为空白名单。
//   - 本函数不提供默认值：未配置 WHITELIST 时取什么默认值由调用方决定。
func mustPopulateWhitelist(raw, source string) *sync.Map {
	whitelist := &sync.Map{}

	if strings.TrimSpace(raw) == "" {
		panic(fmt.Sprintf("配置错误: %s 中的 WHITELIST 为空；空白名单会拒绝全部访问，请填入 IP、主机名或放行令牌", source))
	}
	populateWhitelist(raw, whitelist)
	if whitelistEntryCount(whitelist) == 0 {
		panic(fmt.Sprintf("配置错误: %s 中的 WHITELIST 没有有效条目: %q；空白名单会拒绝全部访问", source, raw))
	}
	return whitelist
}

// mustParseCompressionLevel 解析压缩级别的配置字符串，校验其格式与取值范围并返回结果；格式非法或超出范围时终止启动，不使用默认值掩盖非法配置。
//
// 参数:
//   - raw: 配置中的原始字符串，空字符串表示未配置该级别。
//   - name: 配置项的名称，用于错误提示。
//   - defaultValue: raw 为空时使用的默认压缩级别。
//   - minLevel: 允许的最小压缩级别。
//   - maxLevel: 允许的最大压缩级别。
//
// 返回值:
//   - 解析并校验通过的压缩级别；raw 为空时返回 defaultValue。
//   - 配置格式非法或超出范围时在启动阶段直接 panic，服务不会启动。
func mustParseCompressionLevel(raw, name string, defaultValue, minLevel, maxLevel int) int {
	// 未配置时使用默认值。
	if raw == "" {
		return defaultValue
	}

	// 校验整数格式：整串必须恰好是「可选正负号 + 十进制数字」。
	// 先做字符级校验，再交给 fmt.Sscanf 转换，因为 Sscanf 对 "6x"、"6 " 这类写法是宽容的。
	if !isSignedDecimal(raw) {
		panic(fmt.Sprintf("配置错误: %s 不是合法整数: %q", name, raw))
	}

	// 存储解析后的压缩级别。
	var level int

	// 将格式已确认合法的字符串转换为整数。
	if n, err := fmt.Sscanf(raw, "%d", &level); n != 1 || err != nil {
		panic(fmt.Sprintf("配置错误: %s 不是合法整数: %q", name, raw))
	}

	// 检查解析结果是否落在允许的范围内。
	if level < minLevel || level > maxLevel {
		panic(fmt.Sprintf("配置错误: %s 超出合法范围 [%d, %d]: %d", name, minLevel, maxLevel, level))
	}

	// 返回解析后的压缩级别。
	return level
}

// mustParsePreloadTypes 解析并校验预热类型配置，返回规范化后的类型列表；配置非法时终止启动。
//
// 参数:
//   - raw: PRELOAD_TYPES 的原始值；空字符串（含显式留空）使用默认值。
//   - source: 配置来源说明，用于错误信息（".env" 或 "系统环境变量"）。
//
// 返回值:
//   - 去重后的预热类型列表，元素取自 brotli、gzip、raw。
//
// 说明:
//   - 非法值终止启动，不使用默认值掩盖错误配置：静默回退会让实际预热内容与配置不符。
//   - 显式留空（PRELOAD_TYPES=）同样按默认值处理，因为它与未配置一样无法表达预热意图。
func mustParsePreloadTypes(raw, source string) []string {
	// 未配置或显式留空时使用默认值。
	if strings.TrimSpace(raw) == "" {
		return []string{DefaultPreloadTypes}
	}

	// 按逗号拆分，逐项校验并去重。
	preloadTypes := make([]string, 0, 3)
	seen := make(map[string]struct{}, 3)
	for _, item := range strings.Split(raw, PreloadTypeSeparator) {
		preloadType := strings.TrimSpace(item)
		switch preloadType {
		case PreloadTypeBrotli, PreloadTypeGzip, PreloadTypeRaw:
		default:
			panic(fmt.Sprintf("配置错误: %s 中的 %s 含非法预热类型: %q；合法取值为 %s、%s、%s",
				source, EnvPreloadTypes, preloadType, PreloadTypeBrotli, PreloadTypeGzip, PreloadTypeRaw))
		}
		if _, ok := seen[preloadType]; ok {
			continue
		}
		seen[preloadType] = struct{}{}
		preloadTypes = append(preloadTypes, preloadType)
	}

	return preloadTypes
}

// isSignedDecimal 判断给定字符串是否恰好由「一个可选的正负号」和「一到多位十进制数字」组成。
//
// 参数:
//   - s: 待判断的字符串。
//
// 返回值:
//   - 返回一个布尔值，表示 s 是否为合法的十进制整数字面量；合法返回 true，否则返回 false。
func isSignedDecimal(s string) bool {
	// 空字符串不含任何数字，判为非法。
	if s == "" {
		return false
	}

	// 允许以单个正负号开头，此时跳过该符号继续判断。
	if s[0] == '+' || s[0] == '-' {
		s = s[1:]
	}

	// 正负号之后必须至少有一位数字。
	if s == "" {
		return false
	}

	// 剩余字符必须全部是十进制数字，出现其它字符（如 "6x"、"6.5"、"6 "）即判为非法。
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	// 通过以上检查，判为合法。
	return true
}
