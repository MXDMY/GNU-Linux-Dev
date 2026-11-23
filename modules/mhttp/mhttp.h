
/*
 * http 1.1 客户端实现
 *
 * 传输与内存等底部接口优先使用 mbedtls 实现：
 *   mbedtls_calloc / mbedtls_free
 *   mbedtls_net_init / connect / send / recv_timeout / free
 * 其次使用 m.h 实现，最后使用 C 标准库实现。
 *
 * 未开启 MBEDTLS_NET_C 时，库不提供 mbedtls_net_* 的实现，由用户按
 * mbedtls/net_sockets.h 中的原型自行实现（签名不变）。
 * 替换堆分配请使用 mbedtls_platform_set_calloc_free()（需 MBEDTLS_PLATFORM_MEMORY）。
 *
 * 当前实现：http 1.1 客户端，默认使用长连接：同一句柄在主机、端口、scheme
 * 与 TLS 版本一致时复用连接；响应头 Connection: close、无长度响应读到 EOF、
 * 出错或对端断开时关闭。https 通过 mbedtls TLS 实现，证书校验使用的 CA
 * 文件由下方 MHTTP_CA_FILE 指定，请按目标平台修改。
*/

#ifndef MHTTP_H
#define MHTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mbedtls/net_sockets.h"

#include "m.h"

#define MHTTP_MAX_REQ_SIZE 1024

/* https 校验证书使用的 CA 文件，请按目标平台填写 */
// #define MHTTP_CA_FILE "/etc/ssl/certs/ca-certificates.crt"
#define MHTTP_CA_FILE "/tmp/cert.pem"

/* mhttp_send_req 返回值 */
typedef enum
{
    MHTTP_OK = 0,               // 成功
    MHTTP_ERR_INVALID = -1,     // 参数非法，如 host 为空
    MHTTP_ERR_SCHEME = -2,      // 不支持的 scheme
    MHTTP_ERR_NOMEM = -3,       // 内存不足
    MHTTP_ERR_CONNECT = -4,     // 连接失败
    MHTTP_ERR_SEND = -5,        // 发送失败
    MHTTP_ERR_RECV = -6,        // 接收失败
    MHTTP_ERR_TIMEOUT = -7,     // 接收超时
    MHTTP_ERR_PROTOCOL = -8,    // 响应格式错误
    MHTTP_ERR_TOO_LARGE = -9,   // 请求头或响应体超出限制
    MHTTP_ERR_CALLBACK = -10,   // 响应回调返回非 0
    MHTTP_ERR_TLS = -11         // TLS 初始化或握手失败
}mhttp_result;

typedef struct mhttp_response
{
    int status_code;
    char* reason_phrase;        // 状态码后的原因短语，可能为空串
    char* head;                 // 除状态行外的原始头部块，每行以 CRLF 结尾，无结束空行
    char* body;                 // 响应体，末尾补 '\0'；HEAD/204/304/1xx 时为 NULL
    unsigned long body_len;     // 响应体字节数，body 可能含 '\0'
}mhttp_rsp;

/* 完整 URL (scheme://user:password@host:port/path?query#fragment) + 请求头 + 请求体 */
typedef struct mhttp_request
{
    char* url_scheme;   // http 或 https
    char* url_user;     // 无则置 NULL
    char* url_password; // 无则置 NULL
    char* url_host;
    uint16_t url_port;  // 若置 0（RFC 6335 规定它不应被分配），则使用默认端口
    char* url_path;     // path?query#fragment

    char* method;       // GET、HEAD、POST 等
    char* head;         // 除 Host 字段外的其余头部字段。无则置 NULL
    char* body;         // 无则置 NULL
}mhttp_req;

typedef struct mhttp_handle
{
    mbedtls_net_context context;
    uint8_t is_connected;       // 1 表示 context 当前已连接
    uint8_t tls_ver;            // 当前连接使用的 TLS 版本：0、12、13
    void* tls;                  // 内部 TLS 状态，由 mhttp.c 管理
    char* peer_host;            // 当前连接的主机，用于长连接复用
    uint16_t peer_port;         // 当前连接的端口
}mhttp_hdl;

/* 使用前必须先 init；free 会关闭仍打开的连接 */
extern void mhttp_hdl_init(mhttp_hdl* hdl);
extern void mhttp_hdl_free(mhttp_hdl* hdl);

/*
 * 发送 http 请求（http 或 https，默认复用长连接）
 * @param hdl       连接句柄。若未连接，会先尝试连接
 * @param req       请求消息，字符串只在本次调用期间被引用
 * @param rsp_cb    响应回调函数，置 NULL 则忽略。mhttp_rsp 在回调返回后自动释放，
 *                  需要长期保留数据时请在回调内自行复制
 * @param timeout   单次接收的阻塞等待上限，单位毫秒；0 表示一直等待
 * @param tls       https 使用的 TLS 版本：0 默认（1.2 ~ 1.3），12 仅 TLS 1.2，
 *                  13 仅 TLS 1.3；http 时忽略，其他值返回 MHTTP_ERR_INVALID
 * @return          MHTTP_OK 成功，其余负值见 MHTTP_ERR_*
 * @note            默认复用句柄上的长连接；连接失效或对端要求关闭时会重新连接；
 *                  MHTTP_MAX_REQ_SIZE 只限制请求行与请求头，不限制请求体；
 *                  req.head 需自带每行结尾的 CRLF
*/
extern mhttp_result mhttp_send_req(mhttp_hdl* hdl, mhttp_req req, int (*rsp_cb)(mhttp_rsp), uint32_t timeout, int tls);


#ifdef __cplusplus
}
#endif

#endif

