package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto"
	"golang.org/x/sync/semaphore"
)

func main() {
	var (
		// 存储可能发生的错误的信息。
		err error

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
	// 初始化首页 HTML 缓存。
	serverConfig.IndexHTMLCache = &IndexHTMLCache{}
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

	// 按来源装载配置：存在 .env 时只读该文件，否则读系统环境变量。
	// 两条来源返回同一种映射形状，后续校验与读取逻辑完全共用。
	envVars, source := loadConfigMap()

	// 先校验配置完整性：必需键必须全部显式写出，缺失即终止启动。
	requireKeys(envVars, requiredKeys, source)

	// 再校验必需键的取值：显式留空的键不会套用默认值，一律终止启动。
	for _, key := range requiredKeys {
		requireNonEmpty(envVars, key, source)
	}

	// 必需键已通过完整性与空值校验，这里读取并校验各自的取值。
	// 可选项（PRELOAD_TYPES、GZIP_LEVEL、BROTLI_LEVEL）未配置或留空时用默认值。
	baseURL = envVars["BASE_URL"]
	csvPath = envVars["CSV_PATH"]
	preloadImages = envVars["PRELOAD_IMAGES"]
	serverConfig.IsNetworkPath = mustParseImageURLType(envVars["IMAGE_URL_TYPE"], source)
	serverConfig.Port = mustParsePort(envVars["PORT"], "PORT", source)
	serverConfig.PreloadTypes = mustParsePreloadTypes(envVars[EnvPreloadTypes], source)
	serverConfig.EnableCompression = mustParseBool(envVars["ENABLE_COMPRESSION"], "ENABLE_COMPRESSION", source)
	serverConfig.IndexHtmlPath = envVars["INDEX_HTML_PATH"]
	serverConfig.GzipLevel = mustParseCompressionLevel(envVars["GZIP_LEVEL"], "GZIP_LEVEL", DefaultGzipLevel, MinGzipLevel, MaxGzipLevel)
	serverConfig.BrotliLevel = mustParseCompressionLevel(envVars["BROTLI_LEVEL"], "BROTLI_LEVEL", DefaultBrotliLevel, MinBrotliLevel, MaxBrotliLevel)
	serverConfig.Whitelist = *mustPopulateWhitelist(envVars["WHITELIST"], source)

	// 校验 BASE_URL 的形式：非法取值终止启动，避免装载出空清单后
	// 只留下逐条「跳过越界条目」的告警。
	baseURL = mustValidateBaseURL(baseURL, source, serverConfig.IsNetworkPath)

	// 空白名单会让所有请求被 302，所以在打印清单与启动服务器之前就终止。
	if whitelistEntryCount(&serverConfig.Whitelist) == 0 {
		panic("配置错误: 白名单为空，所有请求都会被重定向；请检查 WHITELIST 配置")
	}

	// 装载图片 URL 清单。
	serverConfig.ImagesUrls = getAndConvertImagesUrlsMap(baseURL, csvPath, serverConfig.IsNetworkPath)

	// 如果环境变量 PRELOAD_IMAGES 设置为 true，则预加载图片到缓存。
	if preloadImages == "true" {
		// 预加载类型由 PRELOAD_TYPES 决定。
		preloadImagesToCache(serverConfig.ImagesUrls, serverConfig.IsNetworkPath, serverConfig.ImagesCache, time.Duration(serverConfig.CacheExpireSeconds)*time.Second, serverConfig.BrotliLevel, serverConfig.GzipLevel, serverConfig.PreloadTypes...)
	}

	// 打印图片清单内容。
	fmt.Println("ImagesUrls:")
	for i, imageURL := range serverConfig.ImagesUrls {
		fmt.Printf("Key: %d, Value: %v\n", i, imageURL)
	}

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
