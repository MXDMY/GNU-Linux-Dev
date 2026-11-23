
/*
 * mhttp 模块（mhttp.h）接口测试。
 *
 * 同一套用例可选择跑在明文或 TLS 上，两种模式互斥，不需要同时启动两个
 * 服务端。以下命令均在工程根目录执行。
 *
 * 一、明文 HTTP
 *   1. 启动服务端：
 *        python3 tmp/http11_server.py --port 18080
 *   2. 运行：
 *        ./build/mhttp_test http 18080
 *
 * 二、https
 *   1. 生成自签证书（SAN 需包含 127.0.0.1）：
 *        openssl req -x509 -newkey rsa:2048 -nodes \
 *          -keyout /tmp/key.pem -out /tmp/cert.pem -days 1 \
 *          -subj "/CN=localhost" \
 *          -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
 *   2. 把 mhttp.h 中的 MHTTP_CA_FILE 改为 "/tmp/cert.pem"，重新编译。
 *   3. 只启动 TLS 服务端（无需明文服务端）：
 *        python3 tmp/http11_server.py --port 18443 --tls \
 *          --cert /tmp/cert.pem --key /tmp/key.pem
 *   4. 运行：
 *        ./build/mhttp_test https 18443 13
 *      第三个参数是 TLS 版本，取 12 或 13，缺省 13。
 *   5. 测试完成后把 MHTTP_CA_FILE 改回系统 CA 路径并重新编译。
 *
 * 三、用法
 *   ./build/mhttp_test [http|https] [port] [tls_ver]
 *   缺省为 http 18080。
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mhttp.h"

#define MHTTP_TEST_DEFAULT_PORT 18080
#define MHTTP_TEST_DEFAULT_TLS_PORT 18443
#define MHTTP_TEST_HEAD_MAX (16 * 1024)
#define MHTTP_TEST_BODY_MAX (128 * 1024)

static int g_passed;
static int g_failed;
static const char* g_scheme;
static int g_port;
static int g_tls_ver;

#define CHECK(cond) \
    do \
    { \
        if (cond) \
            g_passed++; \
        else \
        { \
            g_failed++; \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        } \
    } while (0)

static int g_status;
static char g_reason[128];
static char g_head[MHTTP_TEST_HEAD_MAX];
static unsigned char g_body[MHTTP_TEST_BODY_MAX + 1];
static unsigned long g_body_len;
static int g_body_null;

/*
 * 响应回调：mhttp_rsp 在回调返回后即释放，这里复制需要断言的内容。
 * @param rsp 响应
 * @return    0 继续
*/
static int on_response(mhttp_rsp rsp)
{
    g_status = rsp.status_code;
    g_body_len = rsp.body_len;
    g_body_null = (NULL == rsp.body);

    g_reason[0] = '\0';
    if (rsp.reason_phrase)
        snprintf(g_reason, sizeof(g_reason), "%s", rsp.reason_phrase);

    g_head[0] = '\0';
    if (rsp.head)
        snprintf(g_head, sizeof(g_head), "%s", rsp.head);

    g_body[0] = '\0';
    if (rsp.body && rsp.body_len <= MHTTP_TEST_BODY_MAX)
    {
        memcpy(g_body, rsp.body, rsp.body_len);
        g_body[rsp.body_len] = '\0';
    }

    return 0;
}

/*
 * 发送一次请求并清空上一次的响应缓存。
 * @param hdl        连接句柄
 * @param scheme     http 或 https
 * @param port       端口
 * @param tls        TLS 版本，http 时忽略
 * @param method     方法
 * @param path       请求目标
 * @param body       请求体，可为 NULL
 * @param user       用户名，可为 NULL
 * @param extra_head 额外请求头，可为 NULL
 * @param timeout    单次接收超时
 * @return           mhttp_send_req 的返回值
*/
static mhttp_result do_req_full(mhttp_hdl* hdl, const char* scheme, int port, int tls,
                                const char* method, const char* path, const char* body,
                                const char* user, const char* extra_head, uint32_t timeout)
{
    mhttp_req req;

    memset(&req, 0, sizeof(req));
    req.url_scheme = (char*)scheme;
    req.url_host = "127.0.0.1";
    req.url_port = (uint16_t)port;
    req.url_path = (char*)path;
    req.method = (char*)method;
    req.body = (char*)body;
    req.url_user = (char*)user;
    req.url_password = user ? "pass" : NULL;
    req.head = (char*)extra_head;

    g_status = 0;
    g_body_len = 0;
    g_body_null = 1;
    g_head[0] = '\0';
    g_reason[0] = '\0';

    return mhttp_send_req(hdl, req, on_response, timeout, tls);
}

/*
 * 按当前选择的传输层发送请求的便捷封装。
 * @param hdl    连接句柄
 * @param method 方法
 * @param path   请求目标
 * @param body   请求体，可为 NULL
 * @return       mhttp_send_req 的返回值
*/
static mhttp_result do_req(mhttp_hdl* hdl, const char* method, const char* path, const char* body)
{
    return do_req_full(hdl, g_scheme, g_port, g_tls_ver, method, path, body, NULL, NULL, 2000);
}

/*
 * 响应体是否与给定字符串完全一致。
 * @param text 期望的 C 字符串
 * @return     1 一致，0 不一致
*/
static int body_equals(const char* text)
{
    unsigned long len = (unsigned long)strlen(text);

    return g_body_len == len && 0 == memcmp(g_body, text, len);
}

/*
 * 响应头中是否包含指定子串。
 * @param text 子串
 * @return     1 包含，0 不包含
*/
static int head_contains(const char* text)
{
    return NULL != strstr(g_head, text);
}

/*
 * 从响应头 X-Conn-Id 中取连接 ID。
 * @return 连接 ID；未找到返回 -1
*/
static int conn_id_from_head(void)
{
    const char* p = strstr(g_head, "X-Conn-Id: ");

    return p ? atoi(p + 11) : -1;
}

/*
 * 基础请求与响应字段。
*/
static void test_basic(void)
{
    mhttp_hdl hdl;

    mhttp_hdl_init(&hdl);

    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/get", NULL));
    CHECK(200 == g_status);
    CHECK(0 == strcmp(g_reason, "OK"));
    CHECK(body_equals("get-ok"));
    CHECK(head_contains("Content-Length: 6"));
    CHECK(0 < conn_id_from_head());

    // HEAD：有 Content-Length，但没有响应体
    CHECK(MHTTP_OK == do_req(&hdl, "HEAD", "/head", NULL));
    CHECK(200 == g_status);
    CHECK(0 == g_body_len);
    CHECK(1 == g_body_null);
    CHECK(head_contains("Content-Length: 7"));

    mhttp_hdl_free(&hdl);
}

/*
 * 任意方法字符串。
*/
static void test_methods(void)
{
    static const char* const methods[] =
    {
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
    };
    mhttp_hdl hdl;
    size_t i;

    mhttp_hdl_init(&hdl);

    for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++)
    {
        CHECK(MHTTP_OK == do_req(&hdl, methods[i], "/method", NULL));
        CHECK(200 == g_status);
        CHECK(body_equals(methods[i]));
    }

    CHECK(MHTTP_OK == do_req(&hdl, "CUSTOM", "/method", NULL));
    CHECK(body_equals("CUSTOM"));

    mhttp_hdl_free(&hdl);
}

/*
 * 请求体与响应体的各种成帧方式。
*/
static void test_body_modes(void)
{
    static const unsigned char binary[] = {0x00, 0x01, 0x02, 'A', 'B', 'C', 0x00, 0xFF};
    static const unsigned char chunked_binary[] = {0x00, 0x01, 'A', 'B', 0x00};
    mhttp_hdl hdl;

    mhttp_hdl_init(&hdl);

    // POST 回显
    CHECK(MHTTP_OK == do_req(&hdl, "POST", "/echo", "abc=123"));
    CHECK(200 == g_status);
    CHECK(body_equals("abc=123"));

    // chunked 与 trailer
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/chunked", NULL));
    CHECK(body_equals("hello-chunked"));
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/chunked-trailers", NULL));
    CHECK(body_equals("hello-trailers"));

    // 二进制响应体（含 '\0'）按 body_len 交付
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/binary", NULL));
    CHECK(sizeof(binary) == g_body_len);
    CHECK(0 == memcmp(g_body, binary, sizeof(binary)));

    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/chunked-binary", NULL));
    CHECK(sizeof(chunked_binary) == g_body_len);
    CHECK(0 == memcmp(g_body, chunked_binary, sizeof(chunked_binary)));

    // 无 Content-Length，读到对端关闭
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/no-length", NULL));
    CHECK(body_equals("until-close"));

    // 响应头 Connection: close
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/close", NULL));
    CHECK(body_equals("closed"));

    // 大响应体
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/big?n=65536", NULL));
    CHECK(65536 == g_body_len);
    CHECK('A' == g_body[0]);
    CHECK('A' == g_body[65535]);

    mhttp_hdl_free(&hdl);
}

/*
 * 长连接复用与关闭后重连。
*/
static void test_keep_alive(void)
{
    mhttp_hdl hdl;
    int id1;
    int id2;

    mhttp_hdl_init(&hdl);

    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/get", NULL));
    id1 = conn_id_from_head();
    CHECK(0 < id1);

    // 连续请求应复用同一条连接
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/get", NULL));
    CHECK(id1 == conn_id_from_head());
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/chunked", NULL));
    CHECK(id1 == conn_id_from_head());
    CHECK(MHTTP_OK == do_req(&hdl, "POST", "/echo", "abc"));
    CHECK(id1 == conn_id_from_head());

    // Connection: close 后必须重连
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/close", NULL));
    CHECK(id1 == conn_id_from_head());
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/get", NULL));
    id2 = conn_id_from_head();
    CHECK(id2 != id1);

    // 无长度响应读到 EOF 后必须重连
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/no-length", NULL));
    CHECK(id2 == conn_id_from_head());
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/get", NULL));
    id1 = conn_id_from_head();
    CHECK(id1 != id2);

    // 响应体后有多余数据，下一请求应重连
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/extra-data", NULL));
    CHECK(body_equals("hello"));
    CHECK(id1 == conn_id_from_head());
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/get", NULL));
    CHECK(conn_id_from_head() != id1);

    mhttp_hdl_free(&hdl);
}

/*
 * 自动请求头、自定义请求头、响应头解析。
*/
static void test_headers(void)
{
    mhttp_hdl hdl;

    mhttp_hdl_init(&hdl);

    // Basic 认证：test:pass
    CHECK(MHTTP_OK == do_req_full(&hdl, g_scheme, g_port, g_tls_ver, "GET", "/auth", NULL, "test", NULL, 2000));
    CHECK(body_equals("Basic dGVzdDpwYXNz"));

    // 自定义请求头
    CHECK(MHTTP_OK == do_req_full(&hdl, g_scheme, g_port, g_tls_ver, "GET", "/header?name=X-Test",
                                  NULL, NULL, "X-Test: abc\r\n", 2000));
    CHECK(body_equals("abc"));

    // 自动生成的 Host 与 Connection
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/header?name=Host", NULL));
    CHECK(NULL != strstr((const char*)g_body, "127.0.0.1"));
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/header?name=Connection", NULL));
    CHECK(body_equals("keep-alive"));

    // 小写响应头名称
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/lowercase-headers", NULL));
    CHECK(body_equals("lower-ok"));

    // chunked 优先于 Content-Length
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/te-and-length", NULL));
    CHECK(body_equals("hello"));

    // 重复响应头
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/multi-headers", NULL));
    CHECK(body_equals("multi"));
    CHECK(head_contains("X-Dup: a"));
    CHECK(head_contains("X-Dup: b"));

    // 空原因短语
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/reason-empty", NULL));
    CHECK(200 == g_status);
    CHECK('\0' == g_reason[0]);
    CHECK(body_equals("ok"));

    mhttp_hdl_free(&hdl);
}

/*
 * 状态码与无响应体状态。
*/
static void test_status(void)
{
    mhttp_hdl hdl;

    mhttp_hdl_init(&hdl);

    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/status?code=404", NULL));
    CHECK(404 == g_status);
    CHECK(body_equals("status-404"));

    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/status?code=204", NULL));
    CHECK(204 == g_status);
    CHECK(0 == g_body_len);
    CHECK(1 == g_body_null);

    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/status?code=304", NULL));
    CHECK(304 == g_status);
    CHECK(0 == g_body_len);
    CHECK(1 == g_body_null);

    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/redirect", NULL));
    CHECK(302 == g_status);
    CHECK(head_contains("Location: /get"));

    mhttp_hdl_free(&hdl);
}

/*
 * 畸形响应：应返回 MHTTP_ERR_PROTOCOL，且之后能重新连接。
*/
static void test_errors(void)
{
    static const char* const paths[] =
    {
        "/bad-status-line", "/bad-chunk", "/short-body",
        "/garbage", "/long-header", "/empty",
    };
    mhttp_hdl hdl;
    size_t i;

    mhttp_hdl_init(&hdl);

    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
    {
        mhttp_result ret = do_req(&hdl, "GET", paths[i], NULL);

        if (MHTTP_ERR_PROTOCOL != ret)
            fprintf(stderr, "    %s returned %d\n", paths[i], (int)ret);
        CHECK(MHTTP_ERR_PROTOCOL == ret);

        CHECK(MHTTP_OK == do_req(&hdl, "GET", "/get", NULL));
        CHECK(body_equals("get-ok"));
    }

    mhttp_hdl_free(&hdl);
}

/*
 * 参数与请求头长度限制。
*/
static void test_limits(void)
{
    static char big_head[1200];
    mhttp_hdl hdl;
    mhttp_req req;

    memset(big_head, 'a', sizeof(big_head) - 1);
    big_head[sizeof(big_head) - 1] = '\0';

    mhttp_hdl_init(&hdl);

    // 请求行+请求头超过 MHTTP_MAX_REQ_SIZE
    CHECK(MHTTP_ERR_TOO_LARGE == do_req_full(&hdl, g_scheme, g_port, g_tls_ver, "GET", "/get",
                                             NULL, NULL, big_head, 2000));

    // hdl 为 NULL
    memset(&req, 0, sizeof(req));
    CHECK(MHTTP_ERR_INVALID == mhttp_send_req(NULL, req, on_response, 1000, 0));

    // host 为 NULL
    memset(&req, 0, sizeof(req));
    req.url_scheme = (char*)g_scheme;
    req.method = "GET";
    CHECK(MHTTP_ERR_INVALID == mhttp_send_req(&hdl, req, on_response, 1000, 0));

    // 不支持的 scheme
    memset(&req, 0, sizeof(req));
    req.url_scheme = "ftp";
    req.url_host = "127.0.0.1";
    req.url_port = (uint16_t)g_port;
    req.method = "GET";
    CHECK(MHTTP_ERR_SCHEME == mhttp_send_req(&hdl, req, on_response, 1000, 0));

    // 非法 TLS 版本
    memset(&req, 0, sizeof(req));
    req.url_scheme = "https";
    req.url_host = "127.0.0.1";
    req.url_port = (uint16_t)g_port;
    req.method = "GET";
    CHECK(MHTTP_ERR_INVALID == mhttp_send_req(&hdl, req, on_response, 1000, 11));

    // 连接失败（回环 1 端口通常无人监听）
    CHECK(MHTTP_ERR_CONNECT == do_req_full(&hdl, g_scheme, 1, g_tls_ver, "GET", "/get",
                                           NULL, NULL, NULL, 500));

    // 接收超时：服务端延迟超过 timeout
    CHECK(MHTTP_ERR_TIMEOUT == do_req_full(&hdl, g_scheme, g_port, g_tls_ver, "GET", "/slow?ms=800",
                                           NULL, NULL, NULL, 200));

    // 超时后连接应已关闭，后续请求能重连
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/get", NULL));

    mhttp_hdl_free(&hdl);
}

/*
 * 回调返回非 0 时中止。
 * @param rsp 响应
 * @return    非 0 表示中止
*/
static int on_response_abort(mhttp_rsp rsp)
{
    (void)rsp;

    return 1;
}

static void test_callback(void)
{
    mhttp_hdl hdl;
    mhttp_req req;

    mhttp_hdl_init(&hdl);
    memset(&req, 0, sizeof(req));
    req.url_scheme = (char*)g_scheme;
    req.url_host = "127.0.0.1";
    req.url_port = (uint16_t)g_port;
    req.url_path = "/get";
    req.method = "GET";

    CHECK(MHTTP_ERR_CALLBACK == mhttp_send_req(&hdl, req, on_response_abort, 2000, g_tls_ver));

    // 中止后连接已关闭，后续请求应能重新连接
    CHECK(MHTTP_OK == do_req(&hdl, "GET", "/get", NULL));

    mhttp_hdl_free(&hdl);
}

int main(int argc, char* argv[])
{
    const char* mode = (argc > 1) ? argv[1] : "http";
    mhttp_hdl hdl;

    if (0 == strcmp(mode, "http"))
    {
        g_scheme = "http";
        g_tls_ver = 0;
        g_port = (argc > 2) ? atoi(argv[2]) : MHTTP_TEST_DEFAULT_PORT;
    }
    else if (0 == strcmp(mode, "https"))
    {
        g_scheme = "https";
        g_tls_ver = (argc > 3) ? atoi(argv[3]) : 13;
        g_port = (argc > 2) ? atoi(argv[2]) : MHTTP_TEST_DEFAULT_TLS_PORT;
        if (12 != g_tls_ver && 13 != g_tls_ver)
        {
            fprintf(stderr, "mhttp_test: tls_ver must be 12 or 13\n");
            return 2;
        }
    }
    else
    {
        fprintf(stderr, "usage: %s [http|https] [port] [tls_ver]\n", argv[0]);
        return 2;
    }

    printf("mhttp_test: %s port %d tls %d\n", g_scheme, g_port, g_tls_ver);

    // 预检：区分“连不上”“TLS 握手失败”“超时”，避免提示误导
    mhttp_hdl_init(&hdl);
    {
        mhttp_result ret = do_req(&hdl, "GET", "/get", NULL);

        if (MHTTP_OK != ret)
        {
            mhttp_hdl_free(&hdl);
            fprintf(stderr, "mhttp_test: preflight failed (%d) for %s://127.0.0.1:%d\n",
                    (int)ret, g_scheme, g_port);

            if (MHTTP_ERR_CONNECT == ret)
                fprintf(stderr, "mhttp_test: cannot connect, start tmp/http11_server.py first\n");
            else if (MHTTP_ERR_TLS == ret)
                fprintf(stderr, "mhttp_test: TLS handshake failed, check MHTTP_CA_FILE (\"%s\") "
                                "points to the server certificate and rebuild\n", MHTTP_CA_FILE);
            else if (MHTTP_ERR_TIMEOUT == ret)
                fprintf(stderr, "mhttp_test: preflight timed out\n");

            return 2;
        }
    }
    mhttp_hdl_free(&hdl);

    test_basic();
    test_methods();
    test_body_modes();
    test_keep_alive();
    test_headers();
    test_status();
    test_errors();
    test_limits();
    test_callback();

    printf("mhttp_test: %d passed, %d failed\n", g_passed, g_failed);

    return g_failed ? 1 : 0;
}

