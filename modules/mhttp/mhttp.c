
/*
 * http 1.1 客户端实现。
 * 支持 http 与 https（TLS 1.2/1.3），默认复用长连接；同一句柄在主机、端口、
 * scheme 与 TLS 版本一致时复用连接，对端要求关闭或连接失效时重连。https 的
 * CA 文件由 MHTTP_CA_FILE 指定。
 * 响应解析顺序：状态行 -> 头部 -> 响应体（Content-Length / chunked / 读到关闭）。
 * 头部与响应体均由 mbedtls_calloc 分配，回调返回后由 rsp_free 统一释放。
*/

#include "mhttp.h"

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

#include "mbedtls/base64.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#include "psa/crypto.h"

#define MHTTP_DEFAULT_HTTP_PORT 80
#define MHTTP_DEFAULT_HTTPS_PORT 443
#define MHTTP_READ_CHUNK 1024
#define MHTTP_MAX_LINE_SIZE 8192
#define MHTTP_EOF (-1000)   // 内部标记：对端已关闭

typedef struct
{
    unsigned char* data;
    unsigned long len;
    unsigned long cap;
}mhttp_buf;

/* 统一的传输层：ssl 为 NULL 时走明文，否则走 TLS */
typedef struct
{
    mbedtls_net_context* net;
    mbedtls_ssl_context* ssl;
}mhttp_io;

/* TLS 的 BIO 上下文，需要携带单次接收超时 */
typedef struct
{
    mbedtls_net_context* net;
    uint32_t timeout;
}mhttp_bio;

/* TLS 会话状态，随句柄在多次请求之间复用 */
typedef struct
{
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mhttp_bio bio;
}mhttp_tls;

typedef struct
{
    mhttp_io io;
    unsigned char* data;
    unsigned long cap;
    unsigned long len;
    unsigned long pos;
    uint32_t timeout;
}mhttp_reader;

/* ------------------------------ 动态缓冲区 ------------------------------ */

/*
 * 确保缓冲区容量不小于 need，必要时按 2 倍扩容。
 * @param buf  目标缓冲区
 * @param need 需要的容量
 * @return     MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int buf_reserve(mhttp_buf* buf, unsigned long need)
{
    if (need <= buf->cap)
        return MHTTP_OK;

    unsigned long cap = buf->cap ? buf->cap : 256;
    while (cap < need)
    {
        if (cap > (ULONG_MAX / 2))
            return MHTTP_ERR_TOO_LARGE;
        cap *= 2;
    }

    unsigned char* data = (unsigned char*)mbedtls_calloc(cap, 1);
    if (! data)
        return MHTTP_ERR_NOMEM;

    if (buf->data)
    {
        memcpy(data, buf->data, buf->len);
        mbedtls_free(buf->data);
    }

    buf->data = data;
    buf->cap = cap;
    return MHTTP_OK;
}

/*
 * 在缓冲区末尾追加数据。
 * @param buf  目标缓冲区
 * @param data 待追加数据
 * @param len  数据长度
 * @return     MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int buf_append(mhttp_buf* buf, const void* data, unsigned long len)
{
    if (0 == len)
        return MHTTP_OK;

    if (len > ULONG_MAX - buf->len)
        return MHTTP_ERR_TOO_LARGE;

    int ret = buf_reserve(buf, buf->len + len);
    if (MHTTP_OK != ret)
        return ret;

    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return MHTTP_OK;
}

/*
 * 在缓冲区末尾补 '\0'，便于按 C 字符串使用。
 * @param buf 目标缓冲区
 * @return    MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int buf_terminate(mhttp_buf* buf)
{
    int ret = buf_reserve(buf, buf->len + 1);
    if (MHTTP_OK != ret)
        return ret;

    buf->data[buf->len] = '\0';
    return MHTTP_OK;
}

/*
 * 释放缓冲区。
 * @param buf 目标缓冲区
*/
static void buf_free(mhttp_buf* buf)
{
    if (buf->data)
        mbedtls_free(buf->data);

    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

/* ------------------------------ 传输层抽象 ------------------------------ */

/*
 * TLS 的发送回调。
 * @param ctx 上下文，指向 mhttp_bio
 * @param buf 待发送数据
 * @param len 数据长度
 * @return    同 mbedtls_net_send
*/
static int bio_send(void* ctx, const unsigned char* buf, size_t len)
{
    mhttp_bio* bio = (mhttp_bio*)ctx;
    return mbedtls_net_send(bio->net, buf, len);
}

/*
 * TLS 的接收回调，携带单次接收超时。
 * @param ctx 上下文，指向 mhttp_bio
 * @param buf 接收缓冲区
 * @param len 缓冲区大小
 * @return    同 mbedtls_net_recv_timeout
*/
static int bio_recv(void* ctx, unsigned char* buf, size_t len)
{
    mhttp_bio* bio = (mhttp_bio*)ctx;
    return mbedtls_net_recv_timeout(bio->net, buf, len, bio->timeout);
}

/*
 * 发送数据；ssl 非 NULL 时走 TLS。
 * @param io   传输层
 * @param data 待发送数据
 * @param len  数据长度
 * @return     MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int io_send(mhttp_io* io, const unsigned char* data, unsigned long len)
{
    unsigned long sent = 0;
    while (sent < len)
    {
        int n;

        if (io->ssl)
            n = mbedtls_ssl_write(io->ssl, data + sent, len - sent);
        else
            n = mbedtls_net_send(io->net, data + sent, len - sent);

        if (n > 0)
        {
            sent += (unsigned long)n;
            continue;
        }
        if (0 == n)
            return MHTTP_ERR_SEND;
        if (MBEDTLS_ERR_SSL_WANT_READ == n || MBEDTLS_ERR_SSL_WANT_WRITE == n)
            continue;
        // TLS 1.3 握手后会收到 NewSessionTicket，需要继续读取
        if (MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET == n)
            continue;

        return MHTTP_ERR_SEND;
    }

    return MHTTP_OK;
}

/*
 * 接收数据；ssl 非 NULL 时走 TLS，超时由 BIO 回调负责。
 * @param io      传输层
 * @param buf     接收缓冲区
 * @param len     缓冲区大小
 * @param timeout 明文接收超时，单位毫秒
 * @return        接收字节数、0（对端关闭）或负的错误码
*/
static int io_recv_timeout(mhttp_io* io, unsigned char* buf, unsigned long len, uint32_t timeout)
{
    if (io->ssl)
        return mbedtls_ssl_read(io->ssl, buf, len);

    return mbedtls_net_recv_timeout(io->net, buf, len, timeout);
}

/*
 * 建立 TLS 会话（仅 https）。
 * @param tls     TLS 状态，调用前未初始化
 * @param net     已连接的网络上下文
 * @param host    主机名，用于 SNI 与证书校验
 * @param tls_ver TLS 版本：0 默认，12 仅 1.2，13 仅 1.3
 * @param timeout 单次接收超时，单位毫秒
 * @return        MHTTP_OK 成功，其余见 MHTTP_ERR_*
 * @note          失败时内部已完成初始化，调用方仍需 tls_free 释放
*/
static mhttp_result tls_start(mhttp_tls* tls, mbedtls_net_context* net, const char* host, int tls_ver, uint32_t timeout)
{
    mbedtls_ssl_init(&tls->ssl);
    mbedtls_ssl_config_init(&tls->conf);
    mbedtls_x509_crt_init(&tls->cacert);

    if (PSA_SUCCESS != psa_crypto_init())
        return MHTTP_ERR_TLS;

    if (0 != mbedtls_x509_crt_parse_file(&tls->cacert, MHTTP_CA_FILE))
        return MHTTP_ERR_TLS;

    if (0 != mbedtls_ssl_config_defaults(&tls->conf, MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT))
        return MHTTP_ERR_TLS;

    if (12 == tls_ver)
    {
        mbedtls_ssl_conf_min_tls_version(&tls->conf, MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(&tls->conf, MBEDTLS_SSL_VERSION_TLS1_2);
    }
    else if (13 == tls_ver)
    {
        mbedtls_ssl_conf_min_tls_version(&tls->conf, MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_max_tls_version(&tls->conf, MBEDTLS_SSL_VERSION_TLS1_3);
    }

    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->cacert, NULL);

    if (0 != mbedtls_ssl_setup(&tls->ssl, &tls->conf))
        return MHTTP_ERR_TLS;

    if (0 != mbedtls_ssl_set_hostname(&tls->ssl, host))
        return MHTTP_ERR_TLS;

    tls->bio.net = net;
    tls->bio.timeout = timeout;
    mbedtls_ssl_set_bio(&tls->ssl, &tls->bio, bio_send, bio_recv, NULL);

    for (;;)
    {
        int ret = mbedtls_ssl_handshake(&tls->ssl);

        if (0 == ret)
            return MHTTP_OK;
        if (MBEDTLS_ERR_SSL_WANT_READ == ret || MBEDTLS_ERR_SSL_WANT_WRITE == ret)
            continue;

        return MHTTP_ERR_TLS;
    }
}

/*
 * 释放 TLS 会话。
 * @param tls    TLS 状态
 * @param notify 非 0 时先发送 close_notify
*/
static void tls_free(mhttp_tls* tls, int notify)
{
    if (notify)
        mbedtls_ssl_close_notify(&tls->ssl);

    mbedtls_ssl_free(&tls->ssl);
    mbedtls_ssl_config_free(&tls->conf);
    mbedtls_x509_crt_free(&tls->cacert);
}

/* -------------------------------- 读取器 -------------------------------- */

/*
 * 初始化带超时的接收缓冲。
 * @param r       读取器
 * @param io      传输层（明文或 TLS）
 * @param timeout 单次接收超时，单位毫秒；0 表示一直等待
 * @return        MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int reader_init(mhttp_reader* r, mhttp_io* io, uint32_t timeout)
{
    r->io = *io;
    r->cap = MHTTP_READ_CHUNK;
    r->len = 0;
    r->pos = 0;
    r->timeout = timeout;
    r->data = (unsigned char*)mbedtls_calloc(r->cap, 1);
    if (! r->data)
        return MHTTP_ERR_NOMEM;

    return MHTTP_OK;
}

/*
 * 释放读取器。
 * @param r 读取器
*/
static void reader_free(mhttp_reader* r)
{
    if (r->data)
        mbedtls_free(r->data);

    r->data = NULL;
    r->cap = 0;
    r->len = 0;
    r->pos = 0;
}

/*
 * 把未消费的数据移到缓冲区头部，腾出尾部空间。
 * @param r 读取器
*/
static void reader_compact(mhttp_reader* r)
{
    if (0 == r->pos)
        return;

    if (r->pos < r->len)
        memmove(r->data, r->data + r->pos, r->len - r->pos);

    r->len -= r->pos;
    r->pos = 0;
}

/*
 * 再接收一段数据；缓冲区满时先扩容。
 * @param r 读取器
 * @return  MHTTP_OK 成功；MHTTP_EOF 表示对端关闭；其余见 MHTTP_ERR_*
*/
static int reader_fill(mhttp_reader* r)
{
    reader_compact(r);

    if (r->len == r->cap)
    {
        if (r->cap > (ULONG_MAX / 2))
            return MHTTP_ERR_TOO_LARGE;

        unsigned long cap = r->cap * 2;
        unsigned char* data = (unsigned char*)mbedtls_calloc(cap, 1);
        if (! data)
            return MHTTP_ERR_NOMEM;

        memcpy(data, r->data, r->len);
        mbedtls_free(r->data);
        r->data = data;
        r->cap = cap;
    }

    for (;;)
    {
        int n = io_recv_timeout(&r->io, r->data + r->len, r->cap - r->len, r->timeout);

        if (n > 0)
        {
            r->len += (unsigned long)n;
            return MHTTP_OK;
        }
        if (0 == n)
            return MHTTP_EOF;
        if (MBEDTLS_ERR_SSL_TIMEOUT == n)
            return MHTTP_ERR_TIMEOUT;
        if (MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == n || MBEDTLS_ERR_SSL_CONN_EOF == n
            || MBEDTLS_ERR_NET_CONN_RESET == n)
            return MHTTP_EOF;
        if (MBEDTLS_ERR_SSL_WANT_READ == n || MBEDTLS_ERR_SSL_WANT_WRITE == n)
            continue;
        // TLS 1.3 握手后会收到 NewSessionTicket，需要继续读取
        if (MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET == n)
            continue;

        return MHTTP_ERR_RECV;
    }
}

/*
 * 读取一行（以 CRLF 结尾），返回内容不含 CRLF，并在原缓冲区写入 '\0'。
 * @param r        读取器
 * @param line     输出行首地址，指向读取器内部缓冲区
 * @param line_len 输出行长度
 * @return         MHTTP_OK 成功，其余见 MHTTP_ERR_*
 * @note           line 在下次 reader_fill 后可能失效，调用方需立即使用
*/
static int reader_get_line(mhttp_reader* r, char** line, unsigned long* line_len)
{
    for (;;)
    {
        unsigned long i;
        for (i = r->pos; i + 1 < r->len; i++)
        {
            if ('\r' == r->data[i] && '\n' == r->data[i + 1])
            {
                // 整行一次到达时也要执行单行上限检查
                if (i - r->pos > MHTTP_MAX_LINE_SIZE)
                    return MHTTP_ERR_PROTOCOL;

                *line = (char*)r->data + r->pos;
                *line_len = i - r->pos;
                r->data[i] = '\0';
                r->pos = i + 2;
                return MHTTP_OK;
            }
        }

        if (r->len - r->pos > MHTTP_MAX_LINE_SIZE)
            return MHTTP_ERR_PROTOCOL;

        int ret = reader_fill(r);
        if (MHTTP_EOF == ret)
            return MHTTP_ERR_PROTOCOL;
        if (MHTTP_OK != ret)
            return ret;
    }
}

/*
 * 精确读取 len 字节到 dst。
 * @param r   读取器
 * @param dst 目标地址
 * @param len 字节数
 * @return    MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int reader_read_exact(mhttp_reader* r, unsigned char* dst, unsigned long len)
{
    while (len > 0)
    {
        if (r->pos == r->len)
        {
            int ret = reader_fill(r);
            if (MHTTP_EOF == ret)
                return MHTTP_ERR_PROTOCOL;
            if (MHTTP_OK != ret)
                return ret;
        }

        unsigned long avail = r->len - r->pos;
        unsigned long take = avail < len ? avail : len;
        memcpy(dst, r->data + r->pos, take);
        r->pos += take;
        dst += take;
        len -= take;
    }

    return MHTTP_OK;
}

/*
 * 把剩余数据全部读入 out，直到对端关闭。
 * @param r   读取器
 * @param out 输出缓冲区
 * @return    MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int reader_drain(mhttp_reader* r, mhttp_buf* out)
{
    for (;;)
    {
        if (r->pos < r->len)
        {
            int ret = buf_append(out, r->data + r->pos, r->len - r->pos);
            if (MHTTP_OK != ret)
                return ret;
            r->pos = r->len;
        }

        int ret = reader_fill(r);
        if (MHTTP_EOF == ret)
            return MHTTP_OK;
        if (MHTTP_OK != ret)
            return ret;
    }
}

/* -------------------------------- 解析 ---------------------------------- */

/*
 * 复制指定长度的字符串，并在末尾补 '\0'。
 * @param s   源字符串
 * @param len 长度
 * @return    新字符串；内存不足返回 NULL
*/
static char* str_dup(const char* s, unsigned long len)
{
    char* p = (char*)mbedtls_calloc(len + 1, 1);
    if (! p)
        return NULL;

    memcpy(p, s, len);
    return p;
}

/*
 * 解析十进制无符号整数，只接受纯数字。
 * @param s   输入字符串
 * @param out 输出数值
 * @return    MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int parse_ulong(const char* s, unsigned long* out)
{
    if ('\0' == s[0])
        return MHTTP_ERR_PROTOCOL;

    unsigned long value = 0;
    for (unsigned long i = 0; '\0' != s[i]; i++)
    {
        if (s[i] < '0' || s[i] > '9')
            return MHTTP_ERR_PROTOCOL;

        unsigned long digit = (unsigned long)(s[i] - '0');
        if (value > (ULONG_MAX - digit) / 10)
            return MHTTP_ERR_TOO_LARGE;

        value = value * 10 + digit;
    }

    *out = value;
    return MHTTP_OK;
}

/*
 * 解析状态行，形如 "HTTP/1.1 200 OK"。
 * @param line        状态行内容
 * @param len         状态行长度
 * @param status_code 输出状态码
 * @param reason      输出原因短语首地址（指向 line 内部）
 * @param reason_len  输出原因短语长度
 * @return            MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int parse_status_line(char* line, unsigned long len, int* status_code, char** reason, unsigned long* reason_len)
{
    if (len < 12 || 0 != m_strncmp(line, "HTTP/", 5, 1))
        return MHTTP_ERR_PROTOCOL;

    unsigned long i = 5;
    while (i < len && ' ' != line[i])
        i++;
    while (i < len && ' ' == line[i])
        i++;

    if (i + 3 > len)
        return MHTTP_ERR_PROTOCOL;

    int code = 0;
    for (int k = 0; k < 3; k++)
    {
        if (line[i + k] < '0' || line[i + k] > '9')
            return MHTTP_ERR_PROTOCOL;
        code = code * 10 + (line[i + k] - '0');
    }
    i += 3;

    while (i < len && ' ' == line[i])
        i++;

    *status_code = code;
    *reason = line + i;
    *reason_len = len - i;
    return MHTTP_OK;
}

/*
 * 解析头部，累积原始头部块，并提取 Content-Length 与 Transfer-Encoding。
 * @param r              读取器
 * @param head           输出原始头部块（每行以 CRLF 结尾，不含结束空行）
 * @param content_length 输出 Content-Length
 * @param has_length     Content-Length 是否存在
 * @param chunked        是否使用 chunked 传输
 * @param conn_close     对端是否要求关闭连接
 * @return               MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int parse_headers(mhttp_reader* r, mhttp_buf* head, unsigned long* content_length, int* has_length, int* chunked, int* conn_close)
{
    for (;;)
    {
        char* line;
        unsigned long len;

        int ret = reader_get_line(r, &line, &len);
        if (MHTTP_OK != ret)
            return ret;

        if (0 == len)
            return MHTTP_OK;

        ret = buf_append(head, line, len);
        if (MHTTP_OK != ret)
            return ret;
        ret = buf_append(head, "\r\n", 2);
        if (MHTTP_OK != ret)
            return ret;

        unsigned long colon = 0;
        while (colon < len && ':' != line[colon])
            colon++;
        if (colon >= len)
            continue;

        unsigned long name_len = colon;
        while (name_len > 0 && (' ' == line[name_len - 1] || '\t' == line[name_len - 1]))
            name_len--;

        unsigned long value_start = colon + 1;
        while (value_start < len && (' ' == line[value_start] || '\t' == line[value_start]))
            value_start++;

        unsigned long value_len = len - value_start;
        while (value_len > 0)
        {
            char c = line[value_start + value_len - 1];
            if (' ' != c && '\t' != c)
                break;
            value_len--;
        }
        line[value_start + value_len] = '\0';

        if (14 == name_len && 0 == m_strncmp(line, "content-length", name_len, 0))
        {
            unsigned long value = 0;
            if (MHTTP_OK == parse_ulong(line + value_start, &value))
            {
                *content_length = value;
                *has_length = 1;
            }
        }
        else if (17 == name_len && 0 == m_strncmp(line, "transfer-encoding", name_len, 0))
        {
            if (NULL != m_strstr(line + value_start, "chunked", 0))
                *chunked = 1;
        }
        else if (10 == name_len && 0 == m_strncmp(line, "connection", name_len, 0))
        {
            if (NULL != m_strstr(line + value_start, "close", 0))
                *conn_close = 1;
        }
    }
}

/*
 * 读取并解码 chunked 响应体。
 * @param r    读取器
 * @param body 输出响应体
 * @return     MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int read_chunked_body(mhttp_reader* r, mhttp_buf* body)
{
    for (;;)
    {
        char* line;
        unsigned long len;

        int ret = reader_get_line(r, &line, &len);
        if (MHTTP_OK != ret)
            return ret;

        // 分块大小后可跟扩展，取分号或空白之前的部分
        unsigned long i = 0;
        while (i < len && ';' != line[i] && ' ' != line[i] && '\t' != line[i])
            i++;
        line[i] = '\0';

        if ('\0' == line[0])
            return MHTTP_ERR_PROTOCOL;

        unsigned long chunk = 0;
        for (unsigned long k = 0; '\0' != line[k]; k++)
        {
            char c = line[k];
            unsigned long digit;

            if (c >= '0' && c <= '9')
                digit = (unsigned long)(c - '0');
            else if (c >= 'a' && c <= 'f')
                digit = (unsigned long)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                digit = (unsigned long)(c - 'A' + 10);
            else
                return MHTTP_ERR_PROTOCOL;

            if (chunk > (ULONG_MAX - digit) / 16)
                return MHTTP_ERR_TOO_LARGE;
            chunk = chunk * 16 + digit;
        }

        // 最后一块，随后是 trailer，读到空行结束
        if (0 == chunk)
        {
            for (;;)
            {
                ret = reader_get_line(r, &line, &len);
                if (MHTTP_OK != ret)
                    return ret;
                if (0 == len)
                    return MHTTP_OK;
            }
        }

        unsigned long left = chunk;
        while (left > 0)
        {
            if (r->pos == r->len)
            {
                ret = reader_fill(r);
                if (MHTTP_EOF == ret)
                    return MHTTP_ERR_PROTOCOL;
                if (MHTTP_OK != ret)
                    return ret;
            }

            unsigned long avail = r->len - r->pos;
            unsigned long take = avail < left ? avail : left;
            ret = buf_append(body, r->data + r->pos, take);
            if (MHTTP_OK != ret)
                return ret;

            r->pos += take;
            left -= take;
        }

        unsigned char crlf[2];
        ret = reader_read_exact(r, crlf, 2);
        if (MHTTP_OK != ret)
            return ret;
        if ('\r' != crlf[0] || '\n' != crlf[1])
            return MHTTP_ERR_PROTOCOL;
    }
}

/* ------------------------------ 组包与发送 ------------------------------ */

/*
 * 生成 Basic 认证的 base64 凭据。
 * @param user     用户名
 * @param password 密码，可为 NULL
 * @param buf      输出缓冲区
 * @param size     缓冲区大小
 * @return         MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int build_authorization(const char* user, const char* password, char* buf, unsigned long size)
{
    unsigned long user_len = (unsigned long)strlen(user);
    unsigned long pass_len = password ? (unsigned long)strlen(password) : 0;
    unsigned long plain_len = user_len + 1 + pass_len;

    char* plain = (char*)mbedtls_calloc(plain_len + 1, 1);
    if (! plain)
        return MHTTP_ERR_NOMEM;

    memcpy(plain, user, user_len);
    plain[user_len] = ':';
    if (pass_len > 0)
        memcpy(plain + user_len + 1, password, pass_len);
    plain[plain_len] = '\0';

    unsigned long b64_cap = 4 * ((plain_len + 2) / 3) + 1;
    unsigned char* b64 = (unsigned char*)mbedtls_calloc(b64_cap, 1);
    if (! b64)
    {
        mbedtls_free(plain);
        return MHTTP_ERR_NOMEM;
    }

    size_t olen = 0;
    int ret = mbedtls_base64_encode(b64, b64_cap, &olen, (const unsigned char*)plain, plain_len);
    mbedtls_free(plain);

    if (0 != ret)
    {
        mbedtls_free(b64);
        return MHTTP_ERR_NOMEM;
    }
    if (olen + 1 > size)
    {
        mbedtls_free(b64);
        return MHTTP_ERR_TOO_LARGE;
    }

    memcpy(buf, b64, olen);
    buf[olen] = '\0';
    mbedtls_free(b64);
    return MHTTP_OK;
}

/*
 * 组装请求行与请求头（不含请求体）。
 * @param req     请求消息
 * @param port    端口
 * @param buf     输出缓冲区
 * @param size    缓冲区大小
 * @param out_len 输出实际长度
 * @return        MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int build_request(const mhttp_req* req, int port, char* buf, unsigned long size, unsigned long* out_len)
{
    const char* method = req->method ? req->method : "GET";
    const char* path = (req->url_path && '\0' != req->url_path[0]) ? req->url_path : "/";
    const char* scheme = req->url_scheme ? req->url_scheme : "http";
    unsigned long len = 0;
    int n;

    n = snprintf(buf + len, size - len, "%s %s HTTP/1.1\r\n", method, path);
    if (n < 0 || (unsigned long)n >= size - len)
        return MHTTP_ERR_TOO_LARGE;
    len += (unsigned long)n;

    if ((0 == m_strcmp(scheme, "http", 0) && MHTTP_DEFAULT_HTTP_PORT == port)
        || (0 == m_strcmp(scheme, "https", 0) && MHTTP_DEFAULT_HTTPS_PORT == port))
        n = snprintf(buf + len, size - len, "Host: %s\r\n", req->url_host);
    else
        n = snprintf(buf + len, size - len, "Host: %s:%d\r\n", req->url_host, port);
    if (n < 0 || (unsigned long)n >= size - len)
        return MHTTP_ERR_TOO_LARGE;
    len += (unsigned long)n;

    n = snprintf(buf + len, size - len, "Connection: keep-alive\r\n");
    if (n < 0 || (unsigned long)n >= size - len)
        return MHTTP_ERR_TOO_LARGE;
    len += (unsigned long)n;

    if (req->body)
    {
        n = snprintf(buf + len, size - len, "Content-Length: %lu\r\n", (unsigned long)strlen(req->body));
        if (n < 0 || (unsigned long)n >= size - len)
            return MHTTP_ERR_TOO_LARGE;
        len += (unsigned long)n;
    }

    if (req->url_user)
    {
        char auth[512];
        int ret = build_authorization(req->url_user, req->url_password, auth, sizeof(auth));

        if (MHTTP_OK != ret)
            return ret;

        n = snprintf(buf + len, size - len, "Authorization: Basic %s\r\n", auth);
        if (n < 0 || (unsigned long)n >= size - len)
            return MHTTP_ERR_TOO_LARGE;
        len += (unsigned long)n;
    }

    if (req->head)
    {
        unsigned long head_len = (unsigned long)strlen(req->head);
        if (head_len >= size - len)
            return MHTTP_ERR_TOO_LARGE;

        memcpy(buf + len, req->head, head_len);
        len += head_len;
    }

    n = snprintf(buf + len, size - len, "\r\n");
    if (n < 0 || (unsigned long)n >= size - len)
        return MHTTP_ERR_TOO_LARGE;
    len += (unsigned long)n;

    *out_len = len;
    return MHTTP_OK;
}

/* ------------------------------ 响应处理 -------------------------------- */

/*
 * 释放响应内部的动态字段。
 * @param rsp 响应
*/
static void rsp_free(mhttp_rsp* rsp)
{
    if (rsp->reason_phrase)
        mbedtls_free(rsp->reason_phrase);
    if (rsp->head)
        mbedtls_free(rsp->head);
    if (rsp->body)
        mbedtls_free(rsp->body);

    rsp->reason_phrase = NULL;
    rsp->head = NULL;
    rsp->body = NULL;
    rsp->body_len = 0;
}

/*
 * 接收并解析一个完整响应。
 * @param io         传输层
 * @param req        请求消息，用于判断 HEAD 等无响应体的方法
 * @param timeout    单次接收超时，单位毫秒
 * @param rsp        输出响应
 * @param keep_alive 输出连接是否可继续复用
 * @return           MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static int recv_response(mhttp_io* io, const mhttp_req* req, uint32_t timeout, mhttp_rsp* rsp, int* keep_alive)
{
    mhttp_reader reader;
    mhttp_buf head;
    mhttp_buf body;
    char* line = NULL;
    unsigned long line_len = 0;
    char* reason = NULL;
    unsigned long reason_len = 0;
    unsigned long content_length = 0;
    int has_length = 0;
    int chunked = 0;
    int conn_close = 0;
    int no_body = 0;
    int ret;

    memset(&head, 0, sizeof(head));
    memset(&body, 0, sizeof(body));
    *keep_alive = 1;

    ret = reader_init(&reader, io, timeout);
    if (MHTTP_OK != ret)
        return ret;

    ret = reader_get_line(&reader, &line, &line_len);
    if (MHTTP_OK != ret)
        goto out;

    ret = parse_status_line(line, line_len, &rsp->status_code, &reason, &reason_len);
    if (MHTTP_OK != ret)
        goto out;

    rsp->reason_phrase = str_dup(reason, reason_len);
    if (! rsp->reason_phrase)
    {
        ret = MHTTP_ERR_NOMEM;
        goto out;
    }

    ret = parse_headers(&reader, &head, &content_length, &has_length, &chunked, &conn_close);
    if (MHTTP_OK != ret)
        goto out;

    if (conn_close)
        *keep_alive = 0;

    ret = buf_terminate(&head);
    if (MHTTP_OK != ret)
        goto out;

    rsp->head = (char*)head.data;
    head.data = NULL;
    head.len = 0;
    head.cap = 0;

    no_body = (0 == m_strcmp(req->method ? req->method : "GET", "HEAD", 0))
        || 204 == rsp->status_code
        || 304 == rsp->status_code
        || (rsp->status_code >= 100 && rsp->status_code < 200);

    if (no_body)
        ret = MHTTP_OK;
    else if (chunked)
        ret = read_chunked_body(&reader, &body);
    else if (has_length)
    {
        if (ULONG_MAX == content_length)
        {
            ret = MHTTP_ERR_TOO_LARGE;
            goto out;
        }

        ret = buf_reserve(&body, content_length + 1);
        if (MHTTP_OK == ret)
        {
            body.len = content_length;
            ret = reader_read_exact(&reader, body.data, content_length);
        }
    }
    else
    {
        ret = reader_drain(&reader, &body);
        if (MHTTP_OK == ret)
            *keep_alive = 0;   // 读到 EOF，连接已由对端关闭
    }

    if (MHTTP_OK != ret)
        goto out;

    // 响应体之后还有多余数据，连接状态不可信，关闭
    if (reader.pos != reader.len)
        *keep_alive = 0;

    if (! no_body)
    {
        ret = buf_terminate(&body);
        if (MHTTP_OK != ret)
            goto out;

        rsp->body = (char*)body.data;
        rsp->body_len = body.len;
        body.data = NULL;
        body.len = 0;
        body.cap = 0;
    }

out:
    if (MHTTP_OK != ret)
        *keep_alive = 0;

    reader_free(&reader);
    buf_free(&head);
    buf_free(&body);
    return ret;
}

/* ------------------------------ 对外接口 -------------------------------- */

/*
 * 关闭句柄上的连接并释放 TLS 状态。
 * @param hdl    连接句柄
 * @param notify 非 0 时在 TLS 上发送 close_notify
*/
static void hdl_close(mhttp_hdl* hdl, int notify)
{
    if (hdl->tls)
    {
        tls_free((mhttp_tls*)hdl->tls, notify && hdl->is_connected);
        mbedtls_free(hdl->tls);
        hdl->tls = NULL;
    }

    mbedtls_net_free(&hdl->context);

    if (hdl->peer_host)
        mbedtls_free(hdl->peer_host);
    hdl->peer_host = NULL;
    hdl->peer_port = 0;
    hdl->tls_ver = 0;
    hdl->is_connected = 0;
}

/*
 * 建立新连接（含可选 TLS 握手），会先关闭旧连接。
 * @param hdl     连接句柄
 * @param host    主机
 * @param port    端口
 * @param tls_ver TLS 版本：0 明文，12/13 对应 TLS 版本
 * @param timeout 单次接收超时，单位毫秒
 * @return        MHTTP_OK 成功，其余见 MHTTP_ERR_*
*/
static mhttp_result hdl_connect(mhttp_hdl* hdl, const char* host, int port, int tls_ver, uint32_t timeout)
{
    hdl_close(hdl, 0);

    char port_str[8];
    int n = snprintf(port_str, sizeof(port_str), "%d", port);
    if (n < 0 || (unsigned long)n >= sizeof(port_str))
        return MHTTP_ERR_INVALID;

    int ret = mbedtls_net_connect(&hdl->context, host, port_str, MBEDTLS_NET_PROTO_TCP);
    if (0 != ret)
    {
        mbedtls_net_free(&hdl->context);
        return MHTTP_ERR_CONNECT;
    }
    hdl->is_connected = 1;

    hdl->peer_host = str_dup(host, (unsigned long)strlen(host));
    if (! hdl->peer_host)
    {
        hdl_close(hdl, 0);
        return MHTTP_ERR_NOMEM;
    }
    hdl->peer_port = (uint16_t)port;

    if (0 != tls_ver)
    {
        mhttp_tls* tls = (mhttp_tls*)mbedtls_calloc(1, sizeof(mhttp_tls));
        if (! tls)
        {
            hdl_close(hdl, 0);
            return MHTTP_ERR_NOMEM;
        }

        hdl->tls = tls;
        hdl->tls_ver = (uint8_t)tls_ver;
        ret = tls_start(tls, &hdl->context, host, tls_ver, timeout);
        if (MHTTP_OK != ret)
        {
            hdl_close(hdl, 0);
            return ret;
        }
    }

    return MHTTP_OK;
}

/*
 * 判断 TLS 连接能否复用：先处理会话票据等协议数据；若发现残留应用数据或
 * 对端已关闭，则不可复用。
 * @param tls TLS 状态
 * @return    1 可复用，0 不可复用
*/
static int tls_reusable(mhttp_tls* tls)
{
    int readable = mbedtls_ssl_check_pending(&tls->ssl);

    if (! readable)
        readable = (0 != mbedtls_net_poll(tls->bio.net, MBEDTLS_NET_POLL_READ, 0));
    if (! readable)
        return 1;

    uint32_t saved = tls->bio.timeout;
    int keep = 1;

    tls->bio.timeout = 1;
    for (;;)
    {
        unsigned char byte;
        int ret = mbedtls_ssl_read(&tls->ssl, &byte, 1);

        if (MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET == ret)
            continue;
        if (MBEDTLS_ERR_SSL_WANT_READ == ret || MBEDTLS_ERR_SSL_WANT_WRITE == ret
            || MBEDTLS_ERR_SSL_TIMEOUT == ret)
            break;
        if (ret <= 0)
        {
            keep = 0;
            break;
        }

        // 读到了应用数据，说明上个响应的数据没有读干净
        keep = 0;
        break;
    }
    tls->bio.timeout = saved;

    return keep;
}

/*
 * 判断句柄上的连接能否复用。
 * @param hdl     连接句柄
 * @param host    主机
 * @param port    端口
 * @param tls_ver TLS 版本：0 明文，12/13 对应 TLS 版本
 * @return        1 可复用，0 不可复用
*/
static int hdl_reusable(mhttp_hdl* hdl, const char* host, uint16_t port, int tls_ver)
{
    if (! hdl->is_connected || ! hdl->peer_host)
        return 0;
    if (0 != strcmp(hdl->peer_host, host) || hdl->peer_port != port)
        return 0;
    if (hdl->tls_ver != (uint8_t)tls_ver)
        return 0;

    if (hdl->tls)
    {
        if (! tls_reusable((mhttp_tls*)hdl->tls))
            return 0;
    }
    else
    {
        // 明文连接可读，说明对端已关闭或有残留数据
        if (0 != mbedtls_net_poll(&hdl->context, MBEDTLS_NET_POLL_READ, 0))
            return 0;
    }

    return 1;
}

void mhttp_hdl_init(mhttp_hdl* hdl)
{
    if (! hdl)
        return;

    mbedtls_net_init(&hdl->context);
    hdl->is_connected = 0;
    hdl->tls_ver = 0;
    hdl->tls = NULL;
    hdl->peer_host = NULL;
    hdl->peer_port = 0;
}

void mhttp_hdl_free(mhttp_hdl* hdl)
{
    if (! hdl)
        return;

    hdl_close(hdl, 1);
}

mhttp_result mhttp_send_req(mhttp_hdl* hdl, mhttp_req req, int (*rsp_cb)(mhttp_rsp), uint32_t timeout, int tls)
{
    if (! hdl || ! req.url_host)
        return MHTTP_ERR_INVALID;

    const char* scheme = req.url_scheme ? req.url_scheme : "http";
    int https = (0 == m_strcmp(scheme, "https", 0));
    if (! https && 0 != m_strcmp(scheme, "http", 0))
        return MHTTP_ERR_SCHEME;
    if (https && 0 != tls && 12 != tls && 13 != tls)
        return MHTTP_ERR_INVALID;

    int tls_ver = https ? tls : 0;
    int port = (0 != req.url_port) ? (int)req.url_port
        : (https ? MHTTP_DEFAULT_HTTPS_PORT : MHTTP_DEFAULT_HTTP_PORT);

    char req_buf[MHTTP_MAX_REQ_SIZE];
    unsigned long req_len = 0;
    mhttp_result ret = build_request(&req, port, req_buf, sizeof(req_buf), &req_len);
    if (MHTTP_OK != ret)
        return ret;

    if (! hdl_reusable(hdl, req.url_host, (uint16_t)port, tls_ver))
    {
        ret = hdl_connect(hdl, req.url_host, port, tls_ver, timeout);
        if (MHTTP_OK != ret)
            return ret;
    }

    mhttp_io io;
    io.net = &hdl->context;
    io.ssl = hdl->tls ? &((mhttp_tls*)hdl->tls)->ssl : NULL;

    ret = io_send(&io, (const unsigned char*)req_buf, req_len);
    if (MHTTP_OK != ret)
    {
        hdl_close(hdl, 0);
        return ret;
    }

    if (req.body)
    {
        ret = io_send(&io, (const unsigned char*)req.body, (unsigned long)strlen(req.body));
        if (MHTTP_OK != ret)
        {
            hdl_close(hdl, 0);
            return ret;
        }
    }

    mhttp_rsp rsp;
    int keep_alive = 1;
    memset(&rsp, 0, sizeof(rsp));

    ret = recv_response(&io, &req, timeout, &rsp, &keep_alive);
    if (MHTTP_OK == ret && rsp_cb)
    {
        if (0 != rsp_cb(rsp))
            ret = MHTTP_ERR_CALLBACK;
    }
    rsp_free(&rsp);

    if (MHTTP_OK != ret || ! keep_alive)
        hdl_close(hdl, 0);

    return ret;
}

