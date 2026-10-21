package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/sync/semaphore"
)

// handleRequest 处理传入的 HTTP 请求：先做白名单鉴权，通过后再取得并发额度并按路径分发。
//
// 参数:
//   - ctx: 当前的请求上下文。
//   - serverConfig: 包含服务器配置的指针，包括信号量和其他配置信息。
func handleRequest(ctx *fasthttp.RequestCtx, serverConfig *ServerConfig) {
	// 先鉴权再控制并发：不在白名单中的请求直接重定向，不占用并发额度。
	authMiddleware(func(ctx *fasthttp.RequestCtx) {
		handleAllowedRequest(ctx, serverConfig)
	}, &serverConfig.Whitelist)(ctx)

	// 设置缓存策略。
	// 缓存策略:
	//   - 首页成功响应：内容是静态 index.html（随机性由 /random-image 单独提供），
	//     允许浏览器缓存以省流量，并声明 Vary 以免缓存发错编码。
	//     用 private 而非 public：共享缓存/CDN 不缓存首页，访问仍会回源，
	//     白名单对 "/" 的拦截不会被缓存绕过。
	//   - 其余响应（随机图片、错误、重定向）：禁止任何缓存。
	if string(ctx.Path()) == "/" && ctx.Response.StatusCode() == fasthttp.StatusOK {
		// 响应体会随 Accept-Encoding 变化（br/gzip/原始），必须声明 Vary，
		// 否则缓存可能把某一种编码的副本发给不支持该编码的客户端。
		ctx.Response.Header.Set("Vary", "Accept-Encoding")
		ctx.Response.Header.Set("Cache-Control", fmt.Sprintf("private, max-age=%d", int(indexHTMLMaxAge/time.Second)))
		return
	}

	ctx.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate")
	ctx.Response.Header.Set("Pragma", "no-cache")
	ctx.Response.Header.Set("Expires", "0")
}

// handleAllowedRequest 处理已通过白名单校验的请求：先取得并发额度，再按路径分发。
//
// 参数:
//   - ctx: 当前的请求上下文。
//   - serverConfig: 包含服务器配置的指针，包括信号量和其他配置信息。
func handleAllowedRequest(ctx *fasthttp.RequestCtx, serverConfig *ServerConfig) {
	// 声明 err 变量，用于捕获可能的错误。
	var err error

	// 尝试获取信号量，用于控制并发请求数量，避免服务器过载。
	if err = acquireSemaphore(ctx, serverConfig.Sem, semaphoreWaitTimeout); err != nil {
		return
	}

	// 设置 Keep-Alive 相关的响应头。
	ctx.Response.Header.Set("Connection", "keep-alive")
	ctx.Response.Header.Set("Keep-Alive", "timeout=10, max=100")

	// 存储请求头中的 Accept-Encoding 字段，以及据此协商出的压缩方式。
	var acceptEncoding string
	var compressionType string

	// 检查 Accept-Encoding 请求头：取出原始头值，交由协商函数解析。
	acceptEncoding = string(ctx.Request.Header.Peek("Accept-Encoding"))

	// 选择压缩类型：按 q 值排序，排除客户端用 q=0 显式拒绝的编码。
	compressionType = negotiateCompression(parseAcceptEncoding(acceptEncoding), serverConfig.EnableCompression)

	// 根据请求的路径选择不同的处理逻辑。
	processRequestByPath(ctx, serverConfig, compressionType)

	// 请求处理完成，归还并发额度。
	serverConfig.Sem.Release(1)
}

// acquireSemaphore 尝试获取信号量以控制并发请求数量。
//
// 参数:
//   - ctx: 当前的请求上下文。
//   - sem: 指向信号量的指针。
//   - waitTimeout: 等待信号量的最长时间；超时视为服务器过载。
//
// 返回值:
//   - 获取失败时返回错误，并已写入 503 响应。
func acquireSemaphore(ctx *fasthttp.RequestCtx, sem *semaphore.Weighted, waitTimeout time.Duration) error {
	// 过载时快速失败返回 503。
	acquireCtx, cancel := context.WithTimeout(context.Background(), waitTimeout)

	err := sem.Acquire(acquireCtx, 1)
	cancel()

	if err != nil {
		// 等待超时，返回 503 错误表示服务器繁忙
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
	// 获取请求路径（不包括查询参数）
	path := string(ctx.Path())

	// 去除末尾的"/"（如果不是根路径）
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	switch path {
	case "/":
		// 处理根路径请求，返回包含随机图片的 HTML 页面。
		HelloServer(ctx, compressionType, serverConfig)
	case "/random-image":
		// 处理 /random-image 路径请求，返回一张随机图片。
		RandomImageHandler(ctx, serverConfig.ImagesUrls, serverConfig.IsNetworkPath, serverConfig.ImagesCache, compressionType, serverConfig)
	default:
		// 如果请求路径不匹配，返回 404 错误。
		NotFoundHandler(ctx)
	}
}

// startServer 构造并启动 HTTP 服务器，根据提供的配置处理请求。
//
// 参数:
//   - serverConfig: 指向 ServerConfig 结构体的指针，包含服务器配置。
//
// 说明:
//   - fasthttp.ListenAndServe 只设置 Handler，其余字段取默认值，
//     而默认值面向公网时过于宽松：读超时无限、单 IP 连接数不限、
//     请求头解析失败时会把请求内容写进错误日志，因此这里显式设置。
//   - 拒绝非 GET/HEAD 请求，返回 400。。
func startServer(serverConfig *ServerConfig) error {
	return (&fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			handleRequest(ctx, serverConfig)
		},
		ReadTimeout:           serverReadTimeout,
		WriteTimeout:          serverWriteTimeout,
		MaxConnsPerIP:         maxConnsPerIP,
		SecureErrorLogMessage: true,
		GetOnly:               true,
	}).ListenAndServe(":" + serverConfig.Port)
}
