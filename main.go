package main

import (
	// 提供了一个字节缓冲区的操作，主要用于处理字节数据。
	"bytes"

	// MIME 类型处理库，用于解析和生成各种 MIME 类型的字符串。
	"mime"

	// 提供了路径操作的函数，如路径拼接和扩展名提取。
	"path/filepath"

	// 高效的缓存库，用于存储和检索快速访问的数据。
	"github.com/dgraph-io/ristretto"

	// 提供高效的 HTTP 服务器和客户端功能。
	"github.com/valyala/fasthttp"

	// 提供信号量的实现，控制并发访问的数量。
	"golang.org/x/sync/semaphore"

	// 实现 Brotli 压缩和解压缩功能的库。
	"github.com/andybalholm/brotli"

	// 用于 Gzip 格式的压缩和解压缩。
	"compress/gzip"

	// 提供缓冲读取和写入的功能，适用于处理文件或其他 I/O 操作。
	"bufio"

	// 提供格式化 I/O 的功能，如打印到控制台和字符串格式化。
	"fmt"

	// 提供与操作系统交互的功能，如处理文件和目录。
	"os"

	// 提供对字符串的操作函数，如分割、连接和替换字符串等。
	"strings"

	// 提供基本的并发编程原语，如互斥锁和等待组。
	"sync"

	// 提供生成伪随机数的功能。
	"math/rand"

	// 提供时间相关的功能，可以用于随机数生成的种子设置等。
	"time"

	// 提供处理上下文的功能，管理请求的生命周期、取消信号等。
	"context"
)

// 定义 ServerConfig 结构体，用于存储服务器配置。
type ServerConfig struct {
	// 储存图片 URL 的线程安全字典。
	ImagesUrlsSyncMap *sync.Map

	// 图片 URL 的数量。
	ImagesUrlsCount int

	// 图片 URL 的类型，决定如何处理图片 URL。
	IsNetworkPath bool

	// 图片数据缓存。
	ImagesCache *ristretto.Cache

	// 缓存过期时间，单位为秒。
	CacheExpireSeconds int

	// 是否启用压缩
	EnableCompression bool

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

	// 域名和 IP 白名单。
	Whitelist sync.Map

	// 控制并发量的信号量。
	Sem *semaphore.Weighted
}

// 硬编码的 URL 常量
const (
	DefaultImageURL   = "https://http.cat/503"
	ForbiddenImageURL = "https://http.cat/403"
	RedirectURL       = "https://http.cat/599"
)

func main() {
	var (
		// 储存环境变量的字典。
		envVars map[string]string

		// 存储可能发生的错误的信息。
		err error

		// 决定是否使用.env文件中的配置。
		useEnv string

		// 基本 URL，用于拼接图片路径。
		baseURL string

		// CSV 文件的路径，文件内有图片 URL。
		csvPath string

		// 控制是否加载图片到缓存的环境变量。
		preloadImages string

		// 声明 ServerConfig 结构体。
		serverConfig ServerConfig
	)

	// 初始化结构体字段
	// 设置缓存过期时间。
	serverConfig.CacheExpireSeconds = 3600
	// 控制最大并发数量。
	serverConfig.Sem = semaphore.NewWeighted(100)

	// 初始化 ristretto 缓存。
	serverConfig.ImagesCache, err = ristretto.NewCache(&ristretto.Config{
		// 计数器数量，用于频率估计。
		NumCounters: 5000,
		// 最大内存消耗（字节）。
		MaxCost: 512 << 20,
		// 批处理缓存项目的数量。
		BufferItems: 64,
	})
	// 初始化缓存失败则异常退出。
	if err != nil {
		panic(fmt.Sprintf("无法初始化缓存: %v\n", err))
	}

	//	加载 .env 文件中的环境变量。
	envVars, err = loadEnvFile("./.env")
	//	如果加载 .env 文件出现错误，则使用默认配置。
	if err != nil {
		fmt.Printf("加载 .env 文件失败: %v\n", err)
		envVars = map[string]string{"USE_ENV": "false"}
	}

	// 根据 USE_ENV 决定使用 .env 文件还是系统环境变量。
	useEnv = envVars["USE_ENV"]
	if useEnv == "true" {
		// 检查从 .env 文件的获得的配置是否完整。
		checkAndSetDefaultEnvVar(envVars, "BASE_URL", "./images")
		checkAndSetDefaultEnvVar(envVars, "CSV_PATH", "./url.csv")
		checkAndSetDefaultEnvVar(envVars, "IMAGE_URL_TYPE", "localpath")
		checkAndSetDefaultEnvVar(envVars, "PORT", "9000")
		checkAndSetDefaultEnvVar(envVars, "PRELOAD_IMAGES", "false")
		checkAndSetDefaultEnvVar(envVars, "ENABLE_COMPRESSION", "true")
		checkAndSetDefaultEnvVar(envVars, "INDEX_HTML_PATH", "./index.html")
		checkAndSetDefaultEnvVar(envVars, "WHITELIST", "localhost,127.0.0.1")
		// 从 .env 文件中获取配置。
		baseURL = envVars["BASE_URL"]
		csvPath = envVars["CSV_PATH"]
		serverConfig.IsNetworkPath = envVars["IMAGE_URL_TYPE"] == "networkpath"
		serverConfig.Port = envVars["PORT"]
		preloadImages = envVars["PRELOAD_IMAGES"]
		serverConfig.EnableCompression = envVars["ENABLE_COMPRESSION"] == "true"
		fmt.Sscanf(envVars["BROTLI_LEVEL"], "%d", &serverConfig.BrotliLevel)
		fmt.Sscanf(envVars["GZIP_LEVEL"], "%d", &serverConfig.GzipLevel)
		serverConfig.IndexHtmlPath = envVars["INDEX_HTML_PATH"]
		populateWhitelist(envVars["WHITELIST"], &serverConfig.Whitelist)
	} else {
		//	从环境变量中获取配置，若未设置环境变量，则使用默认设置。
		baseURL = getEnv("BASE_URL", "./images")
		csvPath = getEnv("CSV_PATH", "./url.csv")
		serverConfig.IsNetworkPath = getEnv("IMAGE_URL_TYPE", "localpath") == "networkpath"
		serverConfig.Port = getEnv("PORT", "9000")
		preloadImages = getEnv("PRELOAD_IMAGES", "false")
		serverConfig.EnableCompression = getEnv("ENABLE_COMPRESSION", "true") == "true"
		serverConfig.IndexHtmlPath = getEnv("INDEX_HTML_PATH", "./index.html")
		populateWhitelist(getEnv("WHITELIST", "localhost,127.0.0.1"), &serverConfig.Whitelist)
	}

	// 获取图片 URL syncMap 和 URL 数量。
	serverConfig.ImagesUrlsSyncMap, serverConfig.ImagesUrlsCount = getAndConvertImagesUrlsMap(baseURL, csvPath)

	// 如果环境变量 PRELOAD_IMAGES 设置为 true，则预加载图片到缓存。
	if preloadImages == "true" {
		preloadImagesToCache(serverConfig.ImagesUrlsSyncMap, serverConfig.IsNetworkPath, serverConfig.ImagesCache)
	}

	// 打印 sync.Map 字段内容。
	fmt.Println("ImagesUrlsSyncMap:")
	printSyncMap(serverConfig.ImagesUrlsSyncMap)

	// 打印 Whitelist 字段内容。
	fmt.Println("Whitelist:")
	printSyncMap(&serverConfig.Whitelist)

	//	启动 HTTP 服务。
	err = startServer(&serverConfig)
	if err != nil {
		fmt.Printf("服务器启动失败: %v\n", err)
	} else {
		fmt.Println("服务器已经关闭...")
	}
}

// loadEnvFile 从指定的 .env 文件中加载环境变量并返回一个键值对映射。
//
// 参数:
//   - filename: .env 文件的路径。
//
// 返回值:
//   - 一个包含环境变量的字典。
//   - 可能发生的错误信息。
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
	// 确保在函数返回时关闭文件，避免资源泄漏。
	defer file.Close()

	// 创建一个新的扫描器，用于逐行读取文件内容。
	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		// 读取当前行的文本内容。
		line = scanner.Text()

		// 跳过空行和以 # 开头的注释行，使用 strings.TrimSpace 去除行首尾的空白字符。
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 使用 '=' 分隔符将行拆分为键和值。
		// SplitN 函数确保最多拆分为两个部分。
		parts = strings.SplitN(line, "=", 2)
		// 如果行没有被正确拆分为键值对，则返回错误。
		if len(parts) != 2 {
			return nil, fmt.Errorf("在 .env 文件中存在无效行: %s", line)
		}

		// 去除键和值的前后空白字符。
		key = strings.TrimSpace(parts[0])
		value = strings.TrimSpace(parts[1])

		//	将键值对存储到 envVars 中。
		envVars[key] = value
	}

	// 返回解析后的环境变量和可能发生的错误的信息。
	return envVars, scanner.Err()
}

// getEnv 根据提供的键获取环境变量的值，如果不存在则返回默认值。
//
// 参数:
//   - key: 环境变量的名称。
//   - defaultValue: 当环境变量不存在时返回的默认值。
//
// 返回值:
//   - 环境变量的值，如果不存在则返回 defaultValue。
func getEnv(key, defaultValue string) string {
	// 环境变量的值。
	var value string

	// 指示环境变量是否存在。
	var exists bool

	//	如果环境变量存在，则返回其值。
	if value, exists = os.LookupEnv(key); exists {
		return value
	}

	//	否则返回默认值。
	return defaultValue
}

// checkAndSetDefaultEnvVar 检查给定的环境变量映射中是否存在指定的键，如果不存在或者其值为空字符串，则设置该键为提供的默认值。
//
// 参数:
//   - envVars: 一个字符串到字符串的映射，表示环境变量集合。
//   - key: 要检查的环境变量的名称。
//   - defaultValue: 当环境变量不存在或值为空时使用的默认值。
//
// 返回值:
//   - 此函数没有返回值，但可能会在 envVars 映射中插入或更新指定的键值对。
func checkAndSetDefaultEnvVar(envVars map[string]string, key, defaultValue string) {
	// value 用于存储指定键的值，exists 用于指示该键是否存在。
	var value string
	var exists bool

	// 检查 envVars 映射中对应 key 的值是否存在。
	// 如果存在，value 将存储这个值，exists 会被设置为 true；否则，exists 为 false，value 被设置为其类型的零值（空字符串）。
	value, exists = envVars[key]

	// 如果键不存在，或其对应的值为空字符串。
	if !exists || value == "" {
		// 将 envVars 中对应的键设置为提供的默认值。
		envVars[key] = defaultValue
	}
}

// handleRequest 处理传入的 HTTP 请求，并根据请求的路径选择相应的处理逻辑。
//
// 参数:
//   - ctx: 当前的请求上下文。
//   - serverConfig: 包含服务器配置的指针，包括信号量和其他配置信息。
func handleRequest(ctx *fasthttp.RequestCtx, serverConfig *ServerConfig) {
	// 声明 err 变量，用于捕获可能的错误。
	var err error

	// 存储请求头中的 Accept-Encoding 字段。
	var acceptEncoding string

	// 记录根据 Accept-Encoding 字段的值所确定的压缩方式。
	var compressionType string

	// 尝试获取信号量，用于控制并发请求数量，避免服务器过载。
	if err = acquireSemaphore(ctx, serverConfig.Sem); err != nil {
		return
	}
	defer serverConfig.Sem.Release(1)

	// 设置 Keep-Alive 相关的响应头。
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Keep-Alive", "timeout=10, max=100")

	// 检查 Accept-Encoding 请求头。
	acceptEncoding = string(ctx.Request.Header.Peek("Accept-Encoding"))

	// 选择压缩类型。
	if strings.Contains(acceptEncoding, "br") && serverConfig.EnableCompression {
		compressionType = "brotli"
	} else if strings.Contains(acceptEncoding, "gzip") && serverConfig.EnableCompression {
		compressionType = "gzip"
	}

	// 根据请求的路径选择不同的处理逻辑。
	processRequestByPath(ctx, serverConfig, compressionType)
}

// acquireSemaphore 尝试获取信号量以控制并发请求数量。
//
// 参数:
//   - ctx: 当前的请求上下文。
//   - sem: 指向信号量的指针。
func acquireSemaphore(ctx *fasthttp.RequestCtx, sem *semaphore.Weighted) error {
	// 声明 err 变量，用于捕获可能的错误
	var err error

	if err = sem.Acquire(context.Background(), 1); err != nil {
		// 如果获取信号量失败，返回 503 错误表示服务器繁忙
		ctx.Error("服务器忙，请稍后重试", fasthttp.StatusServiceUnavailable)
		return err
	}
	return nil
}

// processRequestByPath 根据请求的路径选择相应的处理逻辑。
//
// 参数:
//   - ctx: 当前的请求上下文。
//   - serverConfig: 包含服务器配置的指针，包括信号量和其他配置信息。
func processRequestByPath(ctx *fasthttp.RequestCtx, serverConfig *ServerConfig, compressionType string) {
	// 声明 handler 变量，用于处理请求。
	handler := authMiddleware(func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/":
			// 处理根路径请求，返回包含随机图片的 HTML 页面。
			HelloServer(ctx, compressionType, serverConfig)
		case "/random-image":
			// 处理 /random-image 路径请求，返回一张随机图片。
			RandomImageHandler(ctx, serverConfig.ImagesUrlsSyncMap, serverConfig.ImagesUrlsCount, serverConfig.IsNetworkPath, serverConfig.ImagesCache, compressionType, serverConfig)
		default:
			// 如果请求路径不匹配，返回 404 错误。
			NotFoundHandler(ctx)
		}
	}, &serverConfig.Whitelist)

	// 直接执行处理程序，处理请求。
	handler(ctx)
}

// startServer 启动一个 HTTP 服务器，根据提供的配置处理请求。
//
// 参数:
//   - serverConfig: 指向 ServerConfig 结构体的指针，包含服务器配置。
func startServer(serverConfig *ServerConfig) error {
	return fasthttp.ListenAndServe(":"+serverConfig.Port, func(ctx *fasthttp.RequestCtx) {
		handleRequest(ctx, serverConfig)
	})
}

// HelloServer 处理 HTTP 请求并返回一个包含随机图片的 HTML 页面。
//
// 参数:
//   - ctx: fasthttp.RequestCtx 请求上下文对象，包含请求和响应的相关信息。
//   - compressionType: 指定压缩类型，支持 "brotli" 或 "gzip"，决定是否及如何压缩响应内容。
//   - serverConfig: ServerConfig 结构体，包含服务器配置，如是否启用压缩及压缩等级。
func HelloServer(ctx *fasthttp.RequestCtx, compressionType string, serverConfig *ServerConfig) {
	// 储存 HTML 内容。
	var htmlContent []byte

	// 压缩过后的 HTML 内容。
	var compressedData bytes.Buffer

	// 可能出现的错误。
	var err error

	// 读取 HTML 文件的内容。
	htmlContent, err = os.ReadFile(serverConfig.IndexHtmlPath)
	if err != nil {
		ctx.Error("无法读取 HTML 文件", fasthttp.StatusInternalServerError)
		return
	}

	if serverConfig.EnableCompression {
		// 根据压缩类型进行压缩。
		if compressionType == "brotli" {
			ctx.Response.Header.Set("Content-Encoding", "br")
			w := brotli.NewWriterLevel(&compressedData, serverConfig.BrotliLevel)
			// 检查写入错误。
			_, err = w.Write(htmlContent)
			if err != nil {
				ctx.Error("写入 brotli 压缩内容失败", fasthttp.StatusInternalServerError)
				return
			}

			// 检查关闭写入器是否出错。
			err = w.Close()
			if err != nil {
				ctx.Error("关闭 brotli 写入器失败", fasthttp.StatusInternalServerError)
				return
			}

			ctx.SetBody(compressedData.Bytes())
		} else if compressionType == "gzip" {
			ctx.Response.Header.Set("Content-Encoding", "gzip")
			w, err := gzip.NewWriterLevel(&compressedData, serverConfig.GzipLevel)
			if err != nil {
				ctx.Error("创建 Gzip 写入器失败", fasthttp.StatusInternalServerError)
				return
			}

			// 检查写入错误。
			_, err = w.Write(htmlContent)
			if err != nil {
				ctx.Error("写入 Gzip 压缩内容失败", fasthttp.StatusInternalServerError)
				return
			}

			// 检查关闭写入器是否出错。
			err = w.Close()
			if err != nil {
				ctx.Error("关闭 Gzip 写入器失败", fasthttp.StatusInternalServerError)
				return
			}
			ctx.SetBody(compressedData.Bytes())
		} else {
			// 不支持的压缩类型。
			// 直接输出 HTML 内容到响应体。
			ctx.SetBody(htmlContent)
			ctx.Error("不支持的压缩类型", fasthttp.StatusInternalServerError)
		}
	} else {
		// 输出 HTML 内容到响应体。
		ctx.SetBody(htmlContent)
	}
	//	设置响应头，指定内容类型为 HTML。
	ctx.SetContentType("text/html")

	//	设置 HTTP 状态码为 200 OK。
	ctx.SetStatusCode(fasthttp.StatusOK)

	//	输出 HTML 内容到响应体。
	//ctx.SetBody(htmlContent)
}

// RandomImageHandler 函数处理随机图片请求。
//
// 参数:
//   - ctx: fasthttp 请求上下文对象，包含请求和响应的相关信息。
//   - imagesUrlsSyncMap: 指向存储图片 URL 的同步映射的指针。
//   - imagesUrlsCount: 可用图片 URL 的数量。
//   - isNetworkPath: 指示图片路径是否为网络路径的布尔值。
//   - ImagesCache: 指向用于缓存图片数据的 Ristretto 缓存的指针。
func RandomImageHandler(ctx *fasthttp.RequestCtx, imagesUrlsSyncMap *sync.Map, imagesUrlsCount int, isNetworkPath bool, ImagesCache *ristretto.Cache, compressionType string, serverConfig *ServerConfig) {
	// 存储随机选择的图片 URL。
	var imagePath string

	// 存储图片数据的字节切片。
	var imageData []byte

	// 存储可能出现的错误的信息。
	var err error

	// 存储文件扩展名，例如 ".jpg"、".png" 等，用于识别图片类型。
	var ext string

	// 存储确定的内容类型，用于设置 HTTP 响应头中的 Content-Type，
	// 例如 "image/jpeg"、"image/png"等，告知客户端返回的数据类型。
	var contentType string

	// 使用 bytes.Buffer 存储压缩后的数据。
	// 该缓冲区用于在压缩数据处理过程中动态存储数据，
	// 最终可以用于直接写入 HTTP 响应或进一步处理。
	var compressedData bytes.Buffer

	//	从图片 URL 数组中随机选择一个 URL。
	imagePath = getRandomImage(imagesUrlsSyncMap, imagesUrlsCount)
	fmt.Println(imagePath)

	// 获取或缓存图片数据。
	imageData, err = getCachedImage(imagePath, isNetworkPath, ImagesCache)
	if err != nil {
		// 如果获取图片失败，返回 HTTP 500 错误，并输出错误信息到控制台。
		ctx.Error("无法读取图片", fasthttp.StatusInternalServerError)
		fmt.Printf("无法读取图片: %v", err)
		return
	}

	// 根据图片文件扩展名设置响应的 Content-Type。
	ext = filepath.Ext(imagePath)
	contentType = mime.TypeByExtension(ext)
	if contentType == "" {
		// 默认内容类型。
		contentType = "application/octet-stream"
	}

	// 设置响应头，指定内容类型。
	ctx.SetContentType(contentType)

	// 设置 HTTP 状态码为 200 OK。
	ctx.SetStatusCode(fasthttp.StatusOK)

	// 输出图片文件内容。
	// 根据压缩类型进行压缩
	if compressionType == "brotli" {
		ctx.Response.Header.Set("Content-Encoding", "br")
		w := brotli.NewWriterLevel(&compressedData, serverConfig.BrotliLevel)

		// 检查写入错误
		_, err = w.Write(imageData)
		if err != nil {
			ctx.Error("写入压缩内容失败", fasthttp.StatusInternalServerError)
			return
		}

		// 检查关闭写入器是否出错
		err = w.Close()
		if err != nil {
			ctx.Error("关闭写入器失败", fasthttp.StatusInternalServerError)
			return
		}

		ctx.SetBody(compressedData.Bytes())

	} else if compressionType == "gzip" {
		ctx.Response.Header.Set("Content-Encoding", "gzip")
		w, err := gzip.NewWriterLevel(&compressedData, serverConfig.GzipLevel) // 使用 NewWriterLevel 来创建压缩器

		if err != nil {
			ctx.Error("压缩失败", fasthttp.StatusInternalServerError)
			return
		}

		// 检查写入错误。
		_, err = w.Write(imageData)
		if err != nil {
			ctx.Error("写入压缩内容失败", fasthttp.StatusInternalServerError)
			return
		}

		// 检查关闭写入器是否出错。
		err = w.Close()
		if err != nil {
			ctx.Error("关闭写入器失败", fasthttp.StatusInternalServerError)
			return
		}

		ctx.SetBody(compressedData.Bytes())

	} else {
		// 无需压缩。
		ctx.SetBody(imageData)
	}

	// 设置 Keep-Alive 相关的响应头。
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Keep-Alive", "timeout=10, max=100")
}

// NotFoundHandler 处理未找到的请求，并返回 404 错误信息。
// 当请求的资源不存在时，该处理程序会被调用。
//
// 参数:
//   - ctx: 指向 fasthttp.RequestCtx 的指针，包含请求和响应的上下文信息。
func NotFoundHandler(ctx *fasthttp.RequestCtx) {
	// 输出 404 错误信息，表示请求的资源未找到。
	// 使用 ctx.Error 方法设置响应状态为 404，并提供相应的错误消息。
	ctx.Error("404 not found", fasthttp.StatusNotFound)
}

// readLines 从给定路径的 CSV 文件中逐行读取内容.
//
// 参数:
//   - path: 文件路径，指向要读取的文件。
//
// 返回值:
//   - 包含拼接 baseURL 后的每行内容的字符串切片。
//   - 如果读取文件失败，返回包含默认 ForbiddenImageURL 的切片。
func readLines(path string) []string {
	var (
		// 存储打开的文件。
		file *os.File

		// 存储可能产生的错误的信息。
		err error

		// 存储从 CSV 文件中读取并处理后的内容。
		lines []string

		// 存储每次从文件中读取的一行内容。
		line string

		// 用于逐行扫描 .env 文件内容。
		scanner *bufio.Scanner
	)

	// 打开指定路径的文件。
	file, err = os.Open(path)
	if err != nil {
		// 如果打开文件时出错，输出错误信息并返回 nil。
		fmt.Printf("打开文件时出错:%v\n", err)
		return nil
	}
	//	确保在函数返回时关闭文件，避免资源泄漏。
	defer file.Close()

	// 读取文件内容并创建逐行扫描器。
	scanner = bufio.NewScanner(file)

	//	遍历每一行。
	for scanner.Scan() {
		// 去除每行内容的首尾空白字符（包括换行符 \r 和 \n）。
		line = strings.TrimSpace(scanner.Text())
		//	如果行内容不为空，则处理该行。
		if line != "" {
			// 将每一行与 baseURL 拼接后添加到数组中，
			// 确保每行路径格式统一，避免多余的 "/"
			lines = append(lines, "/"+strings.TrimPrefix(line, "/"))
		}
	}

	//	检查扫描过程中是否发生错误。
	if err = scanner.Err(); err != nil {
		//	如果读取文件时发生错误，输出错误信息，返回默认值。
		fmt.Println("读取文件时出错:", err)
		return []string{ForbiddenImageURL}
	}

	// 返回所有读取并拼接后的 URL。
	return lines
}

// getRandomImage 函数用于从提供的图片 URL 同步映射中随机选择一个图片 URL 并返回。
// 如果同步映射中没有可用的图片 URL，则返回默认的图片 URL。
//
// 参数:
//   - imagesUrlsSyncMap: 指向包含图片 URL 的同步映射的指针。
//   - imagesUrlsCount: 可用图片 URL 的数量。
//
// 返回值:
//   - 随机选择的图片 URL 字符串。
//   - 如果无法获取图片 URL，则返回默认的 ForbiddenImageURL。
func getRandomImage(imagesUrlsSyncMap *sync.Map, imagesUrlsCount int) string {
	// 检查图片 URL 数组是否为空。
	if imagesUrlsCount == 0 {
		// 如果图片数组为空，则返回默认的图片 URL，表示没有可用的图片。
		return ForbiddenImageURL
	}

	// 设置随机数种子，使用当前时间的纳秒数。
	// 这确保每次调用时生成的随机数不同。
	rand.Seed(time.Now().UnixNano())

	// 从图片 URL 数组中随机选择一个索引。
	// 使用 rand.Intn 函数生成一个 [0, imagesUrlsCount) 范围内的随机整数。
	var id = rand.Intn(imagesUrlsCount)

	// 从 sync.Map 中获取随机选择的图片 URL。
	if value, ok := imagesUrlsSyncMap.Load(id); ok {
		// 如果成功加载到对应的 URL，则将其转换为字符串并返回。
		return value.(string)
	}

	// 如果加载失败，返回默认的图片 URL。
	return ForbiddenImageURL

}

// getCachedImage 函数用于从缓存中获取图片数据，如果缓存中不存在则从网络或本地加载。
//
// 参数:
//   - imagePath: 图片的路径或 URL 。
//   - isNetworkPath: 是否为网络路径的标志。
//   - imagesCache: 指向图片缓存的指针。
//
// 返回值:
//   - 图片的字节数据。
//   - 错误信息（如果存在）。
func getCachedImage(imagePath string, isNetworkPath bool, imagesCache *ristretto.Cache) ([]byte, error) {
	var (
		// 存储图片的字节数据。
		imageData []byte

		// 缓存中加载的图片数据。
		cachedData interface{}

		// 存储可能出现的错误的信息。
		err error

		// 检查缓存中是否有数据。
		found bool

		// HTTP 响应状态码。
		statusCode int
	)

	// 检查缓存中是否有图片数据。
	cachedData, found = imagesCache.Get(imagePath)
	// 如果在缓存中找到图片数据，直接返回数据，无需重新加载。
	if found {
		return cachedData.([]byte), nil
	}

	//	根据路径类型（网络路径或本地路径）选择加载图片的方式。
	if isNetworkPath {
		// 如果是网络路径，使用 fasthttp 库发起 GET 请求以下载图片数据。
		statusCode, imageData, err = fasthttp.Get(nil, imagePath)

		// 检查 HTTP 响应状态码是否为 200 (OK)。
		if statusCode != fasthttp.StatusOK {
			// 如果状态码不是 200，则表示下载失败，返回错误。
			return nil, fmt.Errorf("下载图片失败，HTTP 状态码: %d", statusCode)
		}

		//	检查是否发生了请求错误。
		if err != nil {
			// 如果发生错误，返回详细的错误信息。
			return nil, fmt.Errorf("无法下载图片: %w", err)
		}

	} else {
		// 如果是本地路径，尝试读取本地图片文件内容。
		imageData, err = os.ReadFile(imagePath)
		// 检查文件读取是否发生错误。
		if err != nil {
			// 如果读取失败，返回详细的错误信息。
			return nil, fmt.Errorf("无法读取图片: %w", err)
		}
	}

	// 将加载的图片数据存入缓存中，以便下次请求时可以直接从缓存中获取。
	imagesCache.Set(imagePath, imageData, int64(len(imageData)))
	// 等待缓存写入完成，确保缓存已成功更新。
	imagesCache.Wait()

	// 返回加载的图片数据。
	return imageData, nil
}

// isAllowed 函数用于检查请求的来源（IP 或域名）是否在白名单中。
//
// 参数:
//   - ctx: *fasthttp.RequestCtx 类型的上下文，包含有关当前请求的信息。
//   - whitelist: *sync.Map 类型的白名单映射，存储被允许访问的 IP 地址和域名。
//
// 返回值:
//   - 返回一个布尔值，表示请求的来源是否被允许，如果来源在白名单中返回 true，
//     否则返回 false。
func isAllowed(ctx *fasthttp.RequestCtx, whitelist *sync.Map) bool {
	// 去除端口部分的远程地址（IP）。
	var remoteIP string

	// 标志变量，表示远程 IP 是否在白名单中。
	var ipAllowed bool

	// 标志变量，表示请求的域名是否在白名单中。
	var hostAllowed bool

	// 从请求的上下文中提取远程地址，使用 ":" 分割字符串，只取 IP 部分。
	remoteIP = strings.Split(ctx.RemoteAddr().String(), ":")[0]

	// 如果白名单包含 "0.0.0.0/0"，表示允许所有 IPv4
	if _, ipAllowed = whitelist.Load("0.0.0.0"); ipAllowed {
		return true
	}

	// 如果白名单包含 "::/0"，表示允许所有 IPv6
	if _, ipAllowed = whitelist.Load("::/0"); ipAllowed {
		return true
	}

	// 检查远程 IP 是否在白名单中。
	if _, ipAllowed = whitelist.Load(remoteIP); ipAllowed {
		// 如果远程 IP 在白名单中，打印调试信息并返回 true。
		fmt.Println("ipAllowed")
		fmt.Println(ipAllowed)
		return true
	}

	// 检查请求的域名（Host）是否存在于白名单中。
	if _, hostAllowed = whitelist.Load(string(ctx.Host())); hostAllowed {
		fmt.Println("hostAllowed")
		fmt.Println(hostAllowed)
		return true
	}

	// 如果白名单包含 "*"，表示允许所有域名
	if _, hostAllowed = whitelist.Load("*"); hostAllowed {
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
		// 使用 isAllowed 函数（假设存在）来判断当前请求 ctx 是否允许访问。
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

/* // isValidURL 函数用于检查给定的 URL 是否符合有效性要求，并识别 URL 类型。
// 有效的 URL 类型包括:
//   - "https"：以 "https://" 开头的 URL。
//   - "http"：以 "http://" 开头的 URL。
//   - "localPath"：以 "./" 开头的本地路径。
// 此外，该函数还会检查 URL 中是否包含无效的字符（如控制字符或空格）。
//
// 返回值:
//   - urlType (string)：URL 的类型，可能的值有 "https", "http", "localPath"，
//     或空字符串（表示未知类型）。
//   - urlResult (bool)：URL 的有效性，若包含无效字符或不符合已知类型则为 false。
// 通过检查链接的开头以 "http" 或 "https" 开头，并且不包含非法字符。
func isValidURL(urlStr string) (string, bool) {
	// 储存 URL 类型。
	var urlType string

	// 储存 URL 检查结果。
	var urlResult bool

	// 检查 URL 类型。
	//   - 如果 URL 以 "https://" 开头，则将 urlType 设为 "https" 表示其为 HTTPS URL。
	//   - 如果 URL 以 "http://" 开头，则将 urlType 设为 "http" 表示其为 HTTP URL。
	//   - 如果 URL 以 "./" 开头，则将 urlType 设为 "localPath" 表示其为本地相对路径。
	//   - 如果以上条件都不满足，将 urlType 设为空字符串，且将 urlResult 设为 false 表示无效 URL。
	if strings.HasPrefix(urlStr, "https://") {
		urlType = "https"
	}else if strings.HasPrefix(urlStr, "http://") {
	    urlType = "http"
	}else if strings.HasPrefix(urlStr, "./") {
	    urlType = "localPath"
	}else{
		// 未知类型：URL 不以支持的前缀开头，标记为无效。
		urlType = ""
	}

	// 检查控制字符。
	//   - 控制字符通常位于 ASCII 范围 0x00-0x1F 和 0x7F，它们在 URL 中是无效的。
	//   - 遍历 URL 字符串中的每个字符，并判断是否包含控制字符。
	//   - 一旦发现控制字符，将 urlResult 设置为 false 并跳出循环，因为发现一个无效字符
	//     就足以判定 URL 无效。
	for _, c := range urlStr {
		if c <= 0x1F || c == 0x7F {
			// 控制字符包括 0x00-0x1F 和 0x7F
			urlResult = false
		}
	}

	// 检查空格字符。
	//   - URL 中不应包含空格，因为空格是无效字符，通常会导致解析问题。
	//   - 使用 strings.Contains 检查 URL 中是否有空格，若有则将 urlResult 设置为 false。
	if strings.Contains(urlStr, " ") {
		urlResult = false
	}

	// 返回结果。
	//   - urlType 表示 URL 的类型（如 "https", "http", "localPath" 或空字符串）。
	//   - urlResult 表示 URL 是否有效，若为 false 则表明 URL 包含无效字符或类型不支持。
	return urlType, urlResult
} */

// printSyncMap 打印 sync.Map 中所有键值对。
//
// 参数:
//   - m: 要打印的 sync.Map 指针。
func printSyncMap(m *sync.Map) {
	// 使用 Range 方法遍历 sync.Map 中的每个键值对。
	m.Range(func(key, value interface{}) bool {
		// 打印当前键和值的内容。
		fmt.Printf("Key: %v, Value: %v\n", key, value)
		// 返回 true 以继续遍历下一个键值对。
		return true
	})
}

// preloadImagesToCache 预加载图片到缓存中。
//
// 参数:
//   - imagesUrlsSyncMap: 包含图片 URL 的 sync.Map。
//   - isNetworkPath: 指示图片 URL 是否为网络路径的布尔值。
//   - imagesCache: 用于存储图片数据的 ristretto 缓存。
func preloadImagesToCache(imagesUrlsSyncMap *sync.Map, isNetworkPath bool, imagesCache *ristretto.Cache) {
	// 遍历 sync.Map 中的每个图片 URL。
	imagesUrlsSyncMap.Range(func(key, value interface{}) bool {
		var (
			// 图片路径。
			imagePath = value.(string)

			// 图片数据。
			imageData []byte

			// 存储可能发生的错误的信息。
			err error

			// HTTP 请求对象。
			req *fasthttp.Request

			// HTTP 响应对象。
			resp *fasthttp.Response
		)

		if isNetworkPath {
			// 如果是网络路径，从网络加载图片
			// 获取请求和响应对象
			req = fasthttp.AcquireRequest()
			resp = fasthttp.AcquireResponse()

			// 设置请求 URI
			req.SetRequestURI(imagePath)

			// 发送请求，获取图片数据。
			err = fasthttp.Do(req, resp)
			// 如果加载图片数据时发生错误，输出错误信息，继续遍历其他图片路径。
			if err != nil {
				fmt.Printf("从网络加载图片失败: %v\n", err)
				// 释放请求和响应对象。
				fasthttp.ReleaseRequest(req)
				fasthttp.ReleaseResponse(resp)
				return true
			}

			// 检查 HTTP 响应状态码。
			// 如果加载图片数据时发生错误，输出错误信息，继续遍历其他图片路径。
			if resp.StatusCode() != fasthttp.StatusOK {
				fmt.Printf("无法加载图片，HTTP 状态码: %d\n", resp.StatusCode())
				// 释放请求和响应对象
				fasthttp.ReleaseRequest(req)
				fasthttp.ReleaseResponse(resp)
				// 继续遍历其他图片路径。
				return true
			}

			// 获取图片数据
			imageData = resp.Body()

			// 释放请求和响应对象
			fasthttp.ReleaseRequest(req)
			fasthttp.ReleaseResponse(resp)
		} else {
			// 如果是本地路径，从本地文件系统加载图片。
			imageData, err = os.ReadFile(imagePath)
			// 如果加载图片数据时发生错误，输出错误信息。
			if err != nil {
				fmt.Printf("从文件加载图片失败: %v\n", err)
				// 继续遍历其他图片路径。
				return true
			}
		}

		// 将图片数据缓存到 ristretto 缓存中
		if !imagesCache.Set(imagePath, imageData, int64(len(imageData))) {
			fmt.Printf("将图片缓存失败: %s\n", imagePath)
		}

		// 继续遍历其他图片路径。
		return true
	})
}

// populateWhitelist 从给定的白名单字符串中提取主机名，并将其存储到指定的 sync.Map 中。
//
// 参数:
//   - whitelistStr: 以逗号分隔的主机名字符串。
//   - whitelist: 指向存储主机名的 sync.Map 的指针。
func populateWhitelist(whitelistStr string, whitelist *sync.Map) {
	var (
		// 从白名单字符串中分割出来的主机名切片。
		hosts []string

		// 在遍历时用于暂存每个主机名。
		host string
	)

	// 使用 strings.Split 将白名单字符串按逗号分割为多个主机名，并存储到 hosts 切片中。
	hosts = strings.Split(whitelistStr, ",")

	// 遍历分割后的主机名并存储到 whitelist 中
	for _, host = range hosts {
		// 使用 sync.Map 的 Store 方法，将每个主机名存储到 whitelist 中。
		// 这里的 struct{}{} 是一个空结构体，表示只存储主机名的存在性，不占用额外空间。
		whitelist.Store(host, struct{}{})
	}
}

// getAndConvertImagesUrlsMap 从指定的 CSV 文件读取图片 URL，并将其转换为完整的 URL 字典。
//
// 参数:
//   - baseURL: 用于构建完整图片 URL 的基础 URL。
//   - csvPath: 存储图片文件名的 CSV 文件路径。
//
// 返回:
//   - *sync.Map: 存储图片 URL 的字典。
//     int: 图片 URL 的数量。
func getAndConvertImagesUrlsMap(baseURL, csvPath string) (*sync.Map, int) {
	var (
		// 存储可能产生的错误的信息。
		err error

		// 存储图片 URL 的字典，使用 sync.Map 以支持并发安全。
		imagesUrlsMap sync.Map

		// 图片 URL 的数量，初始值为 0。
		imagesUrlsCount int = 0

		// 存储从 CSV 文件读取的每一行内容。
		lines []string

		// 存储 CSV 文件的单行内容。
		line string
	)

	//	检查 CSV 文件是否存在。
	_, err = os.Stat(csvPath)
	if err == nil {
		//	如果文件存在，读取文件内容并处理。
		lines = readLines(csvPath)
		// 遍历每一行，生成完整的图片 URL 并存储到 imagesUrlsMap 中。
		for imagesUrlsCount, line = range lines {
			// 将 baseURL 与当前行内容拼接，形成完整的图片 URL，并存储到字典中。
			imagesUrlsMap.Store(imagesUrlsCount, baseURL+line)

			// 递增图片 URL 的计数。
			imagesUrlsCount++
		}
	} else {
		// 如果文件不存在，使用默认的图片 URL 存储到字典中。
		imagesUrlsMap.Store(1, DefaultImageURL)

		// 将图片 URL 的计数设置为 1，表示只有一个默认 URL。
		imagesUrlsCount = 1

		// 输出错误信息，提示用户 CSV 文件不存在。
		fmt.Println("CSV 文件不存在")
	}

	// 返回存储图片 URL 的字典和图片 URL 的数量。
	return &imagesUrlsMap, imagesUrlsCount
}
