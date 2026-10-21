package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/valyala/fasthttp"
)

// csvLine 是 CSV 中的一条图片条目。
//
// 字段:
//   - number: 条目在文件中的行号，从 1 开始，用于校验失败时定位。
//   - name: 文件中的原始内容，已去掉首尾空白。
//   - path: 归一化后的条目，恒以 "/" 开头，供拼接与校验使用。
type csvLine struct {
	number int
	name   string
	path   string
}

// readLines 从给定路径的 CSV 文件中逐行读取内容。
//
// 参数:
//   - path: 文件路径，指向要读取的文件。
//
// 返回值:
//   - 逐条记录行号、原始内容与归一化路径的条目切片；空行不产生条目。
//   - 读取失败时返回错误，由调用方决定兜底策略，不再伪造兜底 URL。
//
// 说明:
//   - 行号按扫描到的物理行累加，空行同样占一行，因此条目行号与文件一致。
func readLines(path string) ([]csvLine, error) {
	var (
		// 存储打开的文件。
		file *os.File

		// 存储可能产生的错误的信息。
		err error

		// 存储从 CSV 文件中读取并处理后的条目。
		lines []csvLine

		// 存储每次从文件中读取的一行内容。
		line string

		// 当前扫描到的物理行号，从 1 开始。
		lineNumber int

		// 用于逐行扫描 .env 文件内容。
		scanner *bufio.Scanner
	)

	// 打开指定路径的文件。
	file, err = os.Open(path)
	if err != nil {
		// 打开失败时返回错误，由调用方记录并决定兜底策略。
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	// 读取文件内容并创建逐行扫描器。
	scanner = bufio.NewScanner(file)

	//	遍历每一行。
	for scanner.Scan() {
		// 空行也占一行，行号按物理行累加。
		lineNumber++
		// 去除每行内容的首尾空白字符（包括换行符 \r 和 \n）。
		line = strings.TrimSpace(scanner.Text())
		//	如果行内容不为空，则处理该行。
		if line != "" {
			// path 统一补前导 "/"，避免拼接时出现多余的 "/"。
			lines = append(lines, csvLine{
				number: lineNumber,
				name:   line,
				path:   "/" + strings.TrimPrefix(line, "/"),
			})
		}
	}

	//	检查扫描过程中是否发生错误。
	if err = scanner.Err(); err != nil {
		// 忽略关闭失败的返回信息。
		_ = file.Close()
		// 读取过程中出错同样返回错误，避免把半截数据当成有效列表。
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	// 忽略关闭失败的返回信息。
	_ = file.Close()

	// 返回所有读取后的条目。
	return lines, nil
}

// getRandomImage 从提供的图片清单中随机选择一个图片 URL。
//
// 参数:
//   - imagesUrls: 装载后的图片 URL 清单。
//
// 返回值:
//   - 随机选择的图片 URL 字符串；没有可用图片时为空字符串。
//   - 是否成功取得图片 URL；false 表示没有可用图片，调用方应显式返回错误状态。
func getRandomImage(imagesUrls []string) (string, bool) {
	// 检查图片清单是否为空。
	if len(imagesUrls) == 0 {
		// 没有可用图片时返回失败。
		return "", false
	}

	// 从清单中随机取一项。
	return imagesUrls[rand.Intn(len(imagesUrls))], true
}

// imageRequestCoalescer 合并同一张图片、同一编码的并发加载请求。
//
// 缓存未命中到写入缓存之间存在时间窗口；窗口内到达的请求若各自抓取，
// 同一张热点图片会被重复下载或读盘，TTL 到期时最多可达并发上限次。
// 本类型保证同一个 key 同时只有一个请求真正执行加载，其余请求等待并共享结果。
//
// 字段:
//   - mu: 保护 flights 的互斥锁。
//   - flights: key 到进行中加载的映射，条目在加载结束后删除，不会长期增长。
type imageRequestCoalescer struct {
	mu      sync.Mutex
	flights map[string]*imageFlight
}

// imageFlight 记录同一个 key 的一次进行中的加载。
//
// 字段:
//   - done: 本次加载结束时关闭，等待方据此判断结果是否就绪。
//   - data: 加载得到的图片数据。
//   - err: 加载失败时的错误，等待方与发起方拿到同一个错误。
type imageFlight struct {
	done chan struct{}
	data []byte
	err  error
}

// imageRequestCoalescerInstance 是进程内共享的图片加载合并器。
//
// 延迟初始化：测试会直接调用 getCachedImage，不能依赖 main 的构造流程。
var imageRequestCoalescerInstance imageRequestCoalescer

// Do 执行一次带合并的图片加载。
//
// 参数:
//   - key: 合并键，取「图片路径 + 压缩编码」缓存键。
//   - load: 真正执行加载并写入缓存的函数，只在没有同名进行中加载时被调用。
//
// 返回值:
//   - 本次加载（或共享的进行中加载）得到的图片数据与错误。
//
// 说明:
//   - 失败结果同样共享给等待方，且不写入缓存：上游故障时不会让每个请求各等一轮超时。
//   - 发起方 panic 时仍会唤醒等待方并清理条目，随后原样向上抛出 panic。
//   - load 必须负责写入缓存，并保证同一 key 的加载结果可被后续请求复用。
func (c *imageRequestCoalescer) Do(key string, load func() ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	if c.flights == nil {
		c.flights = make(map[string]*imageFlight)
	}
	if flight, ok := c.flights[key]; ok {
		c.mu.Unlock()
		<-flight.done
		return flight.data, flight.err
	}

	// 没有同名加载：由当前请求发起，其他请求等待它的结果。
	flight := &imageFlight{done: make(chan struct{})}
	c.flights[key] = flight
	c.mu.Unlock()

	// 无论 load 正常返回还是 panic，都要唤醒等待方并删除条目。
	defer func() {
		recovered := recover()
		// 把 panic 记为错误。
		if recovered != nil && flight.err == nil {
			flight.err = fmt.Errorf("图片加载发生 panic: %v", recovered)
		}
		close(flight.done)
		c.mu.Lock()
		delete(c.flights, key)
		c.mu.Unlock()
		if recovered != nil {
			// 原样重抛，保持 panic 可见。
			panic(recovered)
		}
	}()

	flight.data, flight.err = load()

	return flight.data, flight.err
}

// imageCacheKey 组合图片路径与压缩类型，作为图片缓存的键。
//
// 参数:
//   - imagePath: 图片的路径或 URL。
//   - compressionType: 压缩类型，"brotli"、"gzip" 或空字符串（不压缩）。
//
// 返回值:
//   - 缓存键；同一张图片的不同编码得到不同的键，互不覆盖。
//
// 说明:
//   - 压缩级别在启动时确定、运行期不再变化，因此键中不需要包含级别。
//   - 用 NUL 分隔编码与路径：路径中不会出现 NUL，因此拼接结果没有歧义。
func imageCacheKey(imagePath, compressionType string) string {
	return compressionType + "\x00" + imagePath
}

// compressImage 按压缩类型压缩图片数据。
//
// 参数:
//   - imageData: 原始图片数据。
//   - compressionType: "brotli"、"gzip"，其它值（含空字符串）表示不压缩。
//   - brotliLevel: brotli 压缩级别。
//   - gzipLevel: gzip 压缩级别。
//
// 返回值:
//   - 压缩后的数据；不压缩时原样返回 imageData。
//   - 压缩失败时的错误。
func compressImage(imageData []byte, compressionType string, brotliLevel, gzipLevel int) ([]byte, error) {
	switch compressionType {
	case "brotli":
		return compressBrotli(imageData, brotliLevel)
	case "gzip":
		return compressGzip(imageData, gzipLevel)
	default:
		return imageData, nil
	}
}

// getCachedImage 从缓存中获取指定编码的图片响应体，未命中时加载原图、压缩后写入缓存。
//
// 参数:
//   - imagePath: 图片的路径或 URL。
//   - isNetworkPath: 是否为网络路径。
//   - imagesCache: 指向图片缓存的指针。
//   - cacheTTL: 缓存条目的存活时间，超时后重新加载，避免图片源更新后一直返回旧图。
//   - compressionType: 协商出的压缩类型，"brotli"、"gzip" 或空字符串（不压缩）。
//   - brotliLevel: brotli 压缩级别。
//   - gzipLevel: gzip 压缩级别。
//
// 返回值:
//   - 已按 compressionType 处理好的响应体字节，可直接写入响应。
//   - 错误信息（如果存在）。
//
// 说明:
//   - 缓存按「图片路径 + 压缩类型」分别存放，命中时无需再次压缩；
//     同一张图片的不同编码各占一条缓存记录。
//   - 未命中时通过 imageRequestCoalescerInstance 合并，避免热点图片被并发重复加载。
//   - 缓存返回的数据由缓存持有，调用方不应修改。
func getCachedImage(imagePath string, isNetworkPath bool, imagesCache *ristretto.Cache, cacheTTL time.Duration, compressionType string, brotliLevel, gzipLevel int) ([]byte, error) {
	// 按路径与编码组合出缓存键。
	cacheKey := imageCacheKey(imagePath, compressionType)

	// 检查缓存中是否已有该编码的响应体。
	if cachedData, found := imagesCache.Get(cacheKey); found {
		// 缓存命中时直接返回数据，无需重新加载与压缩。
		return cachedData.([]byte), nil
	}

	// 未命中：合并同一路径同一编码的并发加载，仅由一个请求执行加载、压缩与写入。
	return imageRequestCoalescerInstance.Do(cacheKey, func() ([]byte, error) {
		// 等待期间可能已有其他请求（含并发加载）填好缓存，命中则不再重复加载。
		if cachedData, found := imagesCache.Get(cacheKey); found {
			return cachedData.([]byte), nil
		}

		imageData, err := loadImage(imagePath, isNetworkPath)
		if err != nil {
			return nil, err
		}

		// 先压缩再缓存：后续同编码的请求直接复用压缩结果。
		compressedData, err := compressImage(imageData, compressionType, brotliLevel, gzipLevel)
		if err != nil {
			return nil, err
		}

		// 将压缩后的图片数据按 TTL 存入缓存，超时后重新加载。
		// 不读取返回值作为判断依据是允许缓存区满而丢弃图片。
		imagesCache.SetWithTTL(cacheKey, compressedData, int64(len(compressedData)), cacheTTL)
		// 等待缓存写入完成。
		imagesCache.Wait()

		// 返回压缩后的图片数据。
		return compressedData, nil
	})
}

// loadImage 按路径类型加载图片数据：网络路径发起 HTTP GET，本地路径读取文件。
//
// 参数:
//   - imagePath: 图片的路径或 URL。
//   - isNetworkPath: 是否为网络路径。
//
// 返回值:
//   - 图片的字节数据。
//   - 加载失败时的错误信息；网络路径的错误已用 %w 保留原始错误。
func loadImage(imagePath string, isNetworkPath bool) ([]byte, error) {
	if isNetworkPath {
		return fetchNetworkImage(imagePath)
	}

	imageData, err := os.ReadFile(imagePath)
	if err != nil {
		return nil, fmt.Errorf("无法读取图片: %w", err)
	}
	// 空文件不是可用的图片：显式失败，避免被 getCachedImage 压缩后写入缓存，
	// 进而在整个 TTL 内持续返回零字节响应。判定与网络分支的响应体检查一致。
	if len(imageData) == 0 {
		return nil, fmt.Errorf("图片文件内容为空")
	}
	return imageData, nil
}

// errImageRedirectRejected 表示图片源要求跳转，但抓取策略禁止重定向。
var errImageRedirectRejected = fmt.Errorf("图片抓取禁止重定向")

// retryableFetchError 标记"可能由被污染的连接引起、值得换一条连接重试一次"的失败。
//
// 只有这一类失败触发重试。确定性失败（重定向、非 200、超过大小上限、连接被拒）
// 重复请求会得到同样结果，重试只会让上游请求数翻倍，因此不在重试范围内。
// 判定用类型断言完成，因此不需要引入 errors 包。
type retryableFetchError struct{ err error }

func (e *retryableFetchError) Error() string { return e.err.Error() }

// fetchNetworkImage 只请求初始 URL：不跟随 Location，总时限为 5 秒。
// 客户端在缓冲读取过程中执行 4 MiB 上限，失败不返回部分图片。
//
// 说明:
//   - 上游若声明与实际不符的 Content-Length（例如谎报 0），fasthttp 会认为响应已结束，
//     剩余正文则滞留在该连接的读缓冲中；连接被放回池后，下一次复用会把残留当作
//     响应头解析，导致间歇性失败（实测同一图源 6 次请求中 3 次报解析错误）。
//   - 这种污染在成功响应上不可观测（CL 与实际正文长度相等），无法据此识别并隔离连接，
//     因此改为对这类失败丢弃池中可能被污染的空闲连接并重试一次；正常路径仍然复用连接。
//   - 只重试 retryableFetchError：保持"一次失败抓取对应一次上游请求"的既有行为，
//     不让 404、重定向、超限等确定性失败产生重复请求。
//   - 两次尝试共享同一个截止时间，总时限仍是 imageFetchTimeout（README 已声明该契约）。
func fetchNetworkImage(imageURL string) ([]byte, error) {
	// 截止时间在循环外计算一次，两次尝试共享同一预算。
	deadline := time.Now().Add(imageFetchTimeout)

	// 与 MaxIdemponentCallAttempts 区分：这是应用层重试，只针对可能被污染的连接；
	// 出站客户端自身的幂等重试仍被禁用。
	const maxAttempts = 2

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		body, err := fetchNetworkImageOnce(imageURL, deadline)
		if err == nil {
			return body, nil
		}
		lastErr = err

		// 确定性失败：重试不会改变结果，直接上抛。
		if _, retryable := err.(*retryableFetchError); !retryable {
			return nil, err
		}

		// 截止时间已过则不再重试：重试只会立刻超时。
		if !time.Now().Before(deadline) {
			break
		}

		// 丢弃池中可能带未读字节的空闲连接，避免重试再次拿到被污染的那条。
		imageHTTPClient.CloseIdleConnections()
	}

	return nil, lastErr
}

// fetchNetworkImageOnce 执行单次抓取；重试与清池由 fetchNetworkImage 负责。
//
// 参数:
//   - imageURL: 图片 URL。
//   - deadline: 本次抓取的截止时间，由调用方统一提供以共享总时限。
func fetchNetworkImageOnce(imageURL string, deadline time.Time) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)
	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI(imageURL)

	// DoDeadline 不自动跳转；截止时间约束本次请求，而非各阶段重新计时。
	if err := imageHTTPClient.DoDeadline(req, resp, deadline); err != nil {
		if err == fasthttp.ErrBodyTooLarge {
			// 超过大小上限属确定性失败，重试不会改变结果。
			return nil, fmt.Errorf("图片响应体超过 %d 字节上限: %w", maxImageResponseBytes, err)
		}
		// 此处判断 DoDeadline 直接返回的错误；不遍历额外包装的错误链。
		timeout, ok := err.(interface{ Timeout() bool })
		if err == fasthttp.ErrTimeout || err == fasthttp.ErrTLSHandshakeTimeout || (ok && timeout.Timeout()) {
			// 超时按确定性失败处理，不重试：预算通常已耗尽，重试只会立刻超时。
			return nil, fmt.Errorf("无法下载图片: %w: %w", fasthttp.ErrTimeout, err)
		}
		// 传输层或响应解析失败：连接可能带未读字节，换一条连接重试即可恢复。
		return nil, &retryableFetchError{err: fmt.Errorf("无法下载图片: %w", err)}
	}
	status := resp.StatusCode()
	if fasthttp.StatusCodeIsRedirect(status) {
		// 不回显 Location：其中可能包含签名或凭据。
		return nil, fmt.Errorf("%w，HTTP 状态码: %d", errImageRedirectRejected, status)
	}
	if status != fasthttp.StatusOK {
		return nil, fmt.Errorf("下载图片失败，HTTP 状态码: %d", status)
	}
	// 空正文不是可用的图片：显式失败，避免被 getCachedImage 压缩后写入缓存，
	// 进而在整个 TTL 内持续返回零字节响应。
	if len(resp.Body()) == 0 {
		return nil, fmt.Errorf("图片响应正文为空")
	}
	// Response 即将归还对象池，必须复制正文，避免缓存引用已复用的缓冲区。
	return append([]byte(nil), resp.Body()...), nil
}

// preloadImagesToCache 预加载图片到缓存中。
//
// 参数:
//   - imagesUrls: 装载后的图片 URL 清单。
//   - isNetworkPath: 指示图片 URL 是否为网络路径的布尔值。
//   - imagesCache: 用于存储图片数据的 ristretto 缓存。
//   - cacheTTL: 缓存条目的存活时间，与运行期按需加载保持一致。
//   - preloadTypes: 决定预热哪些数据，每个元素取值 "brotli"、"gzip"、"raw" 或其它；
//     "brotli" 预热 brotli 结果，"gzip" 预热 gzip 结果，"raw" 及其它值预热原图。
//     传入多个值时逐份预热，重复值只写一次；不传值时不写入任何条目。
//   - brotliLevel: brotli 压缩级别。
//   - gzipLevel: gzip 压缩级别。
//
// 说明:
//   - 无论预热几种数据，每张图片的原图都只加载一次，供各份数据复用；
//     "raw" 对应的数据直接写入缓存，不再压缩。
//   - 未预热的编码由首次请求按需生成并写入缓存。
//   - 逐条写入是异步的，函数结束前会调用一次 Wait() 等待所有写入完成；
//     否则预加载刚结束时到达的请求仍会未命中，对同一张图再加载一次。
func preloadImagesToCache(imagesUrls []string, isNetworkPath bool, imagesCache *ristretto.Cache, cacheTTL time.Duration, brotliLevel, gzipLevel int, preloadTypes ...string) {
	// 预加载的编码集合：与图片缓存的键保持一致，只有 brotli、gzip 会走压缩，
	// 其余（含 "raw"）按原图处理。去重后逐个预热。
	compressionTypes := make([]string, 0, len(preloadTypes))
	seen := make(map[string]struct{}, len(preloadTypes))
	for _, preloadType := range preloadTypes {
		compressionType := ""
		if preloadType == "brotli" || preloadType == "gzip" {
			compressionType = preloadType
		}
		if _, ok := seen[compressionType]; ok {
			continue
		}
		seen[compressionType] = struct{}{}
		compressionTypes = append(compressionTypes, compressionType)
	}

	// 遍历图片清单中的每个图片 URL。
	for _, imagePath := range imagesUrls {

		// 每张图片的原图只加载一次，供所选编码使用。
		imageData, err := loadImage(imagePath, isNetworkPath)
		if err != nil {
			fmt.Printf("预加载图片失败: %v\n", err)
			// 继续遍历其他图片路径。
			continue
		}

		for _, compressionType := range compressionTypes {
			body, err := compressImage(imageData, compressionType, brotliLevel, gzipLevel)
			if err != nil {
				fmt.Printf("预加载压缩图片失败 (%s): %v\n", compressionType, err)
				continue
			}

			// 将结果按 TTL 缓存到 ristretto 缓存中。
			if !imagesCache.SetWithTTL(imageCacheKey(imagePath, compressionType), body, int64(len(body)), cacheTTL) {
				fmt.Printf("将图片缓存失败: %s (%s)\n", imagePath, compressionType)
			}
		}

	}

	// 等待所有预加载写入生效。
	imagesCache.Wait()
}

// urlAuthorityEnd 返回 URL 中 authority 结束的位置，即路径起始的那个 "/" 的下标。
//
// 参数:
//   - u: 完整的 URL，形如 "https://host[:port][/path...]"。
//
// 返回值:
//   - 路径起始 "/" 的下标；URL 没有路径时返回 len(u)；
//     无法识别 "scheme://authority" 形式时返回 -1。
//
// 说明:
//   - 只按 "://" 与随后的首个 "/" 定位，不需要解析 URL 的其它部分。
func urlAuthorityEnd(u string) int {
	i := strings.Index(u, "://")
	if i < 0 {
		return -1
	}

	rest := u[i+3:]
	j := strings.IndexByte(rest, '/')
	if j < 0 {
		return len(u)
	}

	return i + 3 + j
}

// decodePercentOnce 解码一轮百分号编码，并报告是否发生变化。
func decodePercentOnce(s string) (string, bool, bool) {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+2 >= len(s) || hexValue(s[i+1]) < 0 || hexValue(s[i+2]) < 0 {
			return "", false, false
		}
		b.WriteByte(byte(hexValue(s[i+1])<<4 | hexValue(s[i+2])))
		changed = true
		i += 2
	}
	return b.String(), changed, true
}

func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// hasEncodedTraversal 拒绝可能在下游解码后改变路径层级的编码。
// 普通编码文件名（例如 %20、file%2Ename）仍然允许。
func hasEncodedTraversal(path string) bool {
	current := path
	for depth := 0; depth < 3; depth++ {
		decoded, changed, valid := decodePercentOnce(current)
		if !valid {
			return true
		}
		if !changed {
			return false
		}
		if strings.ContainsAny(decoded, "/\\") {
			return true
		}
		for _, segment := range strings.Split(decoded, "/") {
			if segment == "." || segment == ".." {
				return true
			}
		}
		current = decoded
	}
	return true
}

// decodeUTF8Rune 解码一个 UTF-8 字符，不依赖 unicode/utf8。
func decodeUTF8Rune(s string) (rune, int, bool) {
	if len(s) == 0 {
		return 0, 0, false
	}
	b0 := s[0]
	if b0 < 0x80 {
		return rune(b0), 1, true
	}
	if b0 >= 0xc2 && b0 <= 0xdf {
		if len(s) < 2 || s[1]&0xc0 != 0x80 {
			return 0, 0, false
		}
		return rune(b0&0x1f)<<6 | rune(s[1]&0x3f), 2, true
	}
	if b0 >= 0xe0 && b0 <= 0xef {
		if len(s) < 3 || s[1]&0xc0 != 0x80 || s[2]&0xc0 != 0x80 {
			return 0, 0, false
		}
		r := rune(b0&0x0f)<<12 | rune(s[1]&0x3f)<<6 | rune(s[2]&0x3f)
		if r < 0x800 || r >= 0xd800 && r <= 0xdfff {
			return 0, 0, false
		}
		return r, 3, true
	}
	if b0 >= 0xf0 && b0 <= 0xf4 {
		if len(s) < 4 || s[1]&0xc0 != 0x80 || s[2]&0xc0 != 0x80 || s[3]&0xc0 != 0x80 {
			return 0, 0, false
		}
		r := rune(b0&0x07)<<18 | rune(s[1]&0x3f)<<12 | rune(s[2]&0x3f)<<6 | rune(s[3]&0x3f)
		if r < 0x10000 || r > 0x10ffff {
			return 0, 0, false
		}
		return r, 4, true
	}
	return 0, 0, false
}

func isUnicodeSpace(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == 0x00a0 || r == 0x1680 ||
		r >= 0x2000 && r <= 0x200a || r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000
}

func isUnicodeControl(r rune) bool {
	return r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f
}

// validateImageEntry 校验单条图片条目，返回拒绝原因。
//
// 参数:
//   - line: 归一化后的条目，恒以 "/" 开头。
//   - baseURL: 图片基础 URL 或本地目录。
//   - isNetworkPath: 是否为网络路径，决定采用哪套规则。
//
// 返回值:
//   - 合法时返回 nil；否则返回说明具体原因的错误。
//
// 说明:
//   - 这是条目校验的唯一入口，调用方只按错误是否为 nil 决定处置。
//   - 越界防护由上游规则承担：格式层拒绝 "." 与 ".." 段及编码绕过，
//     validateLocalName 保证条目是 base 之内的相对路径
//     （filepath.IsLocal 为真蕴含 Join(base, name) 落在 base 内）。
//   - 平台相关的可寻址性检查委托给 validateLocalName，
//     由构建标签在不同平台提供各自实现。
func validateImageEntry(line, baseURL string, isNetworkPath bool) error {
	// 去掉前导 "/"，按纯文件名/相对路径判断。
	name := strings.TrimPrefix(line, "/")

	if err := validateEntryFormat(name, isNetworkPath); err != nil {
		return err
	}

	if isNetworkPath {
		return nil
	}

	// 本地模式还要保证条目能作为文件名使用：配合 BASE_URL 的校验，
	// 这一条同时蕴含「拼接结果不会逃出 BASE_URL 目录」。
	return validateLocalName(name)
}

// validateEntryFormat 校验条目的格式，与平台无关。
//
// 参数:
//   - name: 去掉前导 "/" 后的条目。
//   - isNetworkPath: 是否为网络路径。
//
// 返回值:
//   - 合法时返回 nil；否则返回说明具体原因的错误。
//
// 说明:
//   - 空白与 ? # \ 只在网络模式拒绝：在网络模式里它们是 URL 的结构字符，
//     会让比较路径与实际请求不一致；在本地模式里它们只是合法的文件名字符。
func validateEntryFormat(name string, isNetworkPath bool) error {
	if name == "" {
		return fmt.Errorf("条目为空")
	}

	if isNetworkPath && strings.ContainsAny(name, "?#\\") {
		return fmt.Errorf("包含 ?、# 或反斜杠；这些字符会让路径与实际请求不一致")
	}

	for i := 0; i < len(name); {
		r, size, ok := decodeUTF8Rune(name[i:])
		if !ok {
			return fmt.Errorf("包含非法的 UTF-8 字节序列")
		}
		if isUnicodeControl(r) {
			return fmt.Errorf("包含控制字符")
		}
		if isNetworkPath && isUnicodeSpace(r) {
			return fmt.Errorf("包含空白字符")
		}
		i += size
	}

	// 编码绕过按 "/" 逐段校验：整串传入会把路径自身的 "/" 误判为解码出的分隔符。
	for _, segment := range strings.Split(name, "/") {
		if hasEncodedTraversal(segment) {
			return fmt.Errorf("包含可能改变层级的百分号编码")
		}
	}

	if hasDotDotSegment(name) {
		return fmt.Errorf("包含 . 或 .. 段")
	}

	return nil
}

// getAndConvertImagesUrlsMap 从指定的 CSV 文件读取图片 URL，并拼接为完整的 URL 清单。
//
// 参数:
//   - baseURL: 用于构建完整图片 URL 的基础 URL。
//   - csvPath: 存储图片文件名的 CSV 文件路径。
//   - isNetworkPath: 指示 baseURL 是网络地址还是本地目录，决定用哪种越界校验。
//
// 返回:
//   - 装载后的图片 URL 清单；为空表示 CSV 缺失、为空或读取失败，没有可用图片。
//
// 说明:
//   - 任一条目校验失败即终止启动，错误消息包含文件名、行号与条目内容：
//     CSV 条目含 ".." 时可读到目录外的文件，这里在装载阶段拦截。
//   - 越界与格式校验统一由 validateImageEntry 完成，装载循环不再区分模式。
func getAndConvertImagesUrlsMap(baseURL, csvPath string, isNetworkPath bool) []string {
	var (
		// 存储可能产生的错误的信息。
		err error

		// 存储装载后的图片 URL 清单。
		imagesUrls []string

		// 存储从 CSV 文件读取的每条条目。
		lines []csvLine

		// 存储 CSV 文件的单条条目。
		entry csvLine
	)

	//	检查 CSV 文件是否存在。
	_, err = os.Stat(csvPath)
	if err != nil {
		// CSV 不存在时不再伪造兜底 URL，返回 0 表示没有可用图片。
		fmt.Printf("CSV 文件不存在: %v\n", err)
		return nil
	}

	//	文件存在，读取文件内容并处理。
	lines, err = readLines(csvPath)
	if err != nil {
		// 读取失败同样视为没有可用图片，交由请求处理时显式返回错误状态。
		fmt.Printf("读取 CSV 文件失败: %v\n", err)
		return nil
	}

	// 逐条校验后拼接为完整路径。
	// 校验失败即终止启动：静默跳过会让 CSV 里的错误一直不被发现，
	// 只在运行期表现为可用图片变少。错误消息带上文件名与行号便于定位。
	for _, entry = range lines {
		if err = validateImageEntry(entry.path, baseURL, isNetworkPath); err != nil {
			panic(fmt.Sprintf("配置错误: CSV 文件 %s 第 %d 行条目 %q 非法: %v",
				csvPath, entry.number, entry.name, err))
		}

		// 将 baseURL 与当前条目拼接，形成完整的图片 URL。
		imagesUrls = append(imagesUrls, baseURL+entry.path)
	}

	// 返回装载后的图片 URL 清单。
	return imagesUrls
}
