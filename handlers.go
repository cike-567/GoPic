package main

import (
	"fmt"
	"mime"
	"path/filepath"
	"strings"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/valyala/fasthttp"
)

// HelloServer 处理 HTTP 请求并返回一个包含随机图片的 HTML 页面。
//
// 参数:
//   - ctx: fasthttp.RequestCtx 请求上下文对象，包含请求和响应的相关信息。
//   - compressionType: 指定压缩类型，支持 "brotli" 或 "gzip"，决定是否及如何压缩响应内容。
//   - serverConfig: ServerConfig 结构体，包含服务器配置，如是否启用压缩及压缩等级。
func HelloServer(ctx *fasthttp.RequestCtx, compressionType string, serverConfig *ServerConfig) {
	// 从缓存取当前编码对应的响应体；文件变化时自动重新读取并压缩。
	body, err := serverConfig.IndexHTMLCache.body(serverConfig.IndexHtmlPath, compressionType, serverConfig.BrotliLevel, serverConfig.GzipLevel)
	if err != nil {
		ctx.Error("无法读取 HTML 文件", fasthttp.StatusInternalServerError)
		fmt.Printf("读取首页 HTML 失败: %v\n", err)
		return
	}

	// 仅在实际使用了压缩编码时声明 Content-Encoding。
	// compressionType 只在启用压缩且客户端接受对应编码时才非空（由 handleRequest 保证）。
	switch compressionType {
	case "brotli":
		ctx.Response.Header.Set("Content-Encoding", "br")
	case "gzip":
		ctx.Response.Header.Set("Content-Encoding", "gzip")
	}

	// SetBody 会把内容复制进响应的 body 缓冲，因此可直接传入共享的缓存切片。
	ctx.SetBody(body)
	//	设置响应头，指定内容类型为 HTML。
	ctx.SetContentType("text/html")

	//	设置 HTTP 状态码为 200 OK。
	ctx.SetStatusCode(fasthttp.StatusOK)
}

// RandomImageHandler 函数处理随机图片请求。
//
// 参数:
//   - ctx: fasthttp 请求上下文对象，包含请求和响应的相关信息。
//   - imagesUrls: 装载后的图片 URL 清单。
//   - isNetworkPath: 指示图片路径是否为网络路径的布尔值。
//   - ImagesCache: 指向用于缓存图片数据的 Ristretto 缓存的指针。
func RandomImageHandler(ctx *fasthttp.RequestCtx, imagesUrls []string, isNetworkPath bool, ImagesCache *ristretto.Cache, compressionType string, serverConfig *ServerConfig) {
	// 存储随机选择的图片 URL。
	var imagePath string

	// 指示是否成功取得可用图片 URL。
	var imageAvailable bool

	// 存储图片数据的字节切片。
	var imageData []byte

	// 存储可能出现的错误的信息。
	var err error

	// 存储文件扩展名，例如 ".jpg"、".png" 等，用于识别图片类型。
	var ext string

	// 存储确定的内容类型，用于设置 HTTP 响应头中的 Content-Type，
	// 例如 "image/jpeg"、"image/png"等，告知客户端返回的数据类型。
	var contentType string

	//	从图片 URL 数组中随机选择一个 URL。
	imagePath, imageAvailable = getRandomImage(imagesUrls)
	if !imageAvailable {
		// CSV 缺失、为空或索引不一致时没有可用图片：
		// 显式返回 503，而不是用伪造的 URL 去读文件。
		fmt.Println("没有可用的图片")
		ctx.Error("没有可用的图片", fasthttp.StatusServiceUnavailable)
		return
	}
	fmt.Println(imagePath)

	// 获取或缓存图片数据。
	imageData, err = getCachedImage(imagePath, isNetworkPath, ImagesCache, time.Duration(serverConfig.CacheExpireSeconds)*time.Second, compressionType, serverConfig.BrotliLevel, serverConfig.GzipLevel)
	if err != nil {
		// 如果获取图片失败，返回 HTTP 500 错误，并输出错误信息到控制台。
		ctx.Error("无法读取图片", fasthttp.StatusInternalServerError)
		fmt.Printf("无法读取图片: %v", err)
		return
	}

	// 根据图片文件扩展名设置响应的 Content-Type。
	// imagePath 在网络路径下是完整 URL，可能带查询串或片段，
	// 因此先剥离它们再取扩展名，否则 "?v=1" 会被当成扩展名的一部分。
	ext = filepath.Ext(stripQueryAndFragment(imagePath))
	contentType = mime.TypeByExtension(ext)
	if contentType == "" {
		// 默认内容类型。
		contentType = "application/octet-stream"
	}

	// 设置 HTTP 状态码为 200 OK。
	ctx.SetStatusCode(fasthttp.StatusOK)

	// 仅在实际使用了压缩编码时声明 Content-Encoding；
	// 响应体已由 getCachedImage 按该编码压缩并缓存，此处直接写出。
	switch compressionType {
	case "brotli":
		ctx.Response.Header.Set("Content-Encoding", "br")
	case "gzip":
		ctx.Response.Header.Set("Content-Encoding", "gzip")
	}
	ctx.SetBody(imageData)

	// 设置响应头，指定内容类型。
	ctx.SetContentType(contentType)
}

// stripQueryAndFragment 去掉 URL 或路径中 "?" 与 "#" 及其之后的部分。
//
// 参数:
//   - path: 图片的路径或 URL。
//
// 返回值:
//   - 不含查询串与片段的部分；两者都不存在时原样返回。
//
// 说明:
//   - 只用于扩展名推断：缓存键与抓取仍使用完整 URL。
func stripQueryAndFragment(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		return path[:i]
	}
	return path
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
