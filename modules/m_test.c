
/*
 * m 模块（m.h）接口测试。
 * 覆盖 m_malloc / m_free / m_strstr / m_memmem / m_strcmp / m_strncmp /
 * m_strdup / m_strndup / m_strnlen / m_strtok_r / m_trim 的正常路径、边界条件
 * 与错误路径。字符串比较接口只断言返回值符号（< 0 / 0 / > 0），不绑定具体
 * 差值，与 strcmp 系列的约定保持一致。
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "m.h"

static int g_passed;
static int g_failed;

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

/*
 * 把整数归一化为 -1 / 0 / 1，便于只比较符号。
 * @param value 待归一化的值
 * @return 负数返回 -1，零返回 0，正数返回 1
*/
static int sign_of(int value)
{
    if (0 > value)
        return -1;
    if (0 < value)
        return 1;

    return 0;
}

/*
 * 断言返回值符号符合预期，失败时输出接口名、用例下标与归一化符号。
 * @param tag    接口名
 * @param index  用例下标
 * @param expect 期望符号
 * @param value  实际返回值
*/
static void expect_sign(const char* tag, size_t index, int expect, int value)
{
    if (expect == sign_of(value))
        g_passed++;
    else
    {
        g_failed++;
        fprintf(stderr, "FAIL %s case %zu: expect sign %d, got %d\n", tag, index, expect, sign_of(value));
    }
}

/*
 * 测试 m_malloc / m_free：可写性、对齐、零字节、超大申请、NULL 释放、
 * 多块分配互不重叠。
*/
static void test_m_malloc_free(void)
{
    static unsigned long const sizes[] = {1, 7, 64, 255, 4096, 65536};
    size_t i;

    // 不同大小分配后写入并回读首尾字节
    for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
    {
        unsigned char* p = (unsigned char*)m_malloc(sizes[i]);

        CHECK(NULL != p);
        if (! p)
            continue;

        memset(p, 0xA5, sizes[i]);
        CHECK(0xA5 == p[0]);
        CHECK(0xA5 == p[sizes[i] - 1]);

        m_free(p);
    }

    // 返回地址至少满足指针宽度的对齐
    {
        void* p = m_malloc(64);

        CHECK(NULL != p);
        if (p)
        {
            CHECK(0 == ((uintptr_t)p % sizeof(void*)));
            m_free(p);
        }
    }

    // 释放 NULL 不得崩溃
    m_free(NULL);

    // 0 字节申请：返回值可为 NULL 或唯一指针，仅要求可安全释放
    m_free(m_malloc(0));

    // 注：分配失败无法可移植地强制触发；超大请求在 ASan 下会直接终止，故不测试

    // 连续分配多块，地址互不重叠，再逐一释放
    {
        void* blocks[32];
        int k;

        memset(blocks, 0, sizeof(blocks));
        for (k = 0; k < 32; k++)
            blocks[k] = m_malloc(64);

        for (k = 0; k < 32; k++)
            CHECK(NULL != blocks[k]);

        for (k = 0; k < 32; k++)
        {
            int j;

            for (j = k + 1; j < 32; j++)
            {
                if (blocks[k] && blocks[j])
                    CHECK(blocks[k] != blocks[j]);
            }
        }

        for (k = 0; k < 32; k++)
            m_free(blocks[k]);
    }
}

typedef struct
{
    const char* text;
    const char* pattern;
    int cs;     // 非零为区分大小写
    int found;  // 1 期望找到，0 期望返回 NULL
    int index;  // 找到时的相对下标
} strstr_case;

/*
 * 测试 m_strstr：区分/不区分大小写、KMP 失配回退、首次出现、空串与 NULL。
*/
static void test_m_strstr(void)
{
    static const strstr_case cases[] =
    {
        {"hello world", "world", 1, 1, 6},
        {"Hello World", "World", 1, 1, 6},
        {"Hello World", "world", 0, 1, 6},
        {"Hello World", "world", 1, 0, -1},
        {"Hello World", "WORLD", 0, 1, 6},
        {"abcabcabd", "abcabd", 1, 1, 3},
        {"aaaaab", "aaab", 1, 1, 2},
        {"abababab", "ababab", 1, 1, 0},
        {"abababab", "abababa", 1, 1, 0},
        {"xxhello", "hello", 1, 1, 2},
        {"hello", "hello", 1, 1, 0},
        {"hello", "hell", 1, 1, 0},
        {"hello", "hellox", 1, 0, -1},
        {"hello", "", 1, 0, -1},
        {"", "a", 1, 0, -1},
        {"", "", 1, 0, -1},
        {"a", "A", 0, 1, 0},
        {"a", "A", 2, 0, -1},
        {"x1y2z", "1Y2", 0, 1, 1},
        {"abc", "c", 1, 1, 2},
        {"abc", "d", 1, 0, -1},
        {"ABAB", "abab", 0, 1, 0},
        {"ABAB", "ab", 0, 1, 0},
        {"zzzabczzz", "abc", 1, 1, 3},
        {"abcabc", "abc", 1, 1, 0},
        {"aBcAbC", "abc", 0, 1, 0},
        {"aBcAbC", "abc", 1, 0, -1},
        {"aAab", "Aab", 0, 1, 1},
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        const strstr_case* c = &cases[i];
        char* got = m_strstr(c->text, c->pattern, c->cs);
        int ok;

        if (c->found)
            ok = (NULL != got && got == c->text + c->index);
        else
            ok = (NULL == got);

        if (ok)
            g_passed++;
        else
        {
            g_failed++;
            fprintf(stderr, "FAIL m_strstr case %zu: text=[%s] pattern=[%s] cs=%d, expect %s\n",
                i, c->text, c->pattern, c->cs, c->found ? "found" : "NULL");
        }
    }

    // NULL 与空串按接口约定返回 NULL
    CHECK(NULL == m_strstr(NULL, "a", 1));
    CHECK(NULL == m_strstr("a", NULL, 1));
    CHECK(NULL == m_strstr(NULL, NULL, 1));
    CHECK(NULL == m_strstr("", "a", 1));
    CHECK(NULL == m_strstr("a", "", 1));
    CHECK(NULL == m_strstr("", "", 1));

    // 不得改动入参内容
    {
        char text[] = "Hello World";
        char pattern[] = "world";
        char text_copy[sizeof(text)];
        char pattern_copy[sizeof(pattern)];
        char* got;

        memcpy(text_copy, text, sizeof(text));
        memcpy(pattern_copy, pattern, sizeof(pattern));

        got = m_strstr(text, pattern, 0);
        CHECK(NULL != got);
        CHECK(got == text + 6);
        CHECK(0 == memcmp(text, text_copy, sizeof(text)));
        CHECK(0 == memcmp(pattern, pattern_copy, sizeof(pattern)));
    }

    // 与 libc strstr 做差分对照（区分大小写、非空模式）
    {
        static const char* const texts[] =
        {
            "", "a", "ab", "abc", "abcabc", "abababab", "hello world", "zzzabczzz",
        };
        static const char* const patterns[] =
        {
            "a", "ab", "abc", "abcd", "b", "zzz", "world", "abab",
        };
        size_t x;
        size_t y;

        for (x = 0; x < sizeof(texts) / sizeof(texts[0]); x++)
        {
            for (y = 0; y < sizeof(patterns) / sizeof(patterns[0]); y++)
            {
                CHECK(strstr(texts[x], patterns[y]) == m_strstr(texts[x], patterns[y], 1));
            }
        }
    }

    // 长文本末尾命中，覆盖内部动态分配路径
    {
        enum { BIG_TEXT_SIZE = 1024 };
        static char big_text[BIG_TEXT_SIZE + 1];
        char* got;

        memset(big_text, 'x', BIG_TEXT_SIZE);
        big_text[BIG_TEXT_SIZE] = '\0';
        memcpy(big_text + BIG_TEXT_SIZE - 6, "needle", 6);

        got = m_strstr(big_text, "needle", 1);
        CHECK(NULL != got);
        CHECK(got == big_text + BIG_TEXT_SIZE - 6);
    }
}

typedef struct
{
    const char* s1;
    const char* s2;
    int cs;
    int sign;
} cmp_case;

/*
 * 测试 m_strcmp：相等、大小写、前后缀、NULL、空串，并与 libc 差分对照。
*/
static void test_m_strcmp(void)
{
    static const cmp_case cases[] =
    {
        {"abc", "abc", 1, 0},
        {"ABC", "abc", 0, 0},
        {"HeLLo", "hello", 0, 0},
        {"aBc", "AbC", 0, 0},
        {"abc", "ABC", 1, 1},
        {"ABC", "abc", 1, -1},
        {"abc", "abd", 1, -1},
        {"abd", "abc", 1, 1},
        {"abc", "abcd", 1, -1},
        {"abcd", "abc", 1, 1},
        {"", "", 1, 0},
        {"", "a", 1, -1},
        {"a", "", 1, 1},
        {"HeLLo", "hellp", 0, -1},
        {"HeLLo", "hellp", 1, -1},
        {"abc", "ABC", 2, 1},
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        const cmp_case* c = &cases[i];

        expect_sign("m_strcmp", i, c->sign, m_strcmp(c->s1, c->s2, c->cs));
    }

    // NULL 参与比较时的约定：均为 NULL 相等，单边 NULL 一侧大/小
    CHECK(0 == sign_of(m_strcmp(NULL, NULL, 1)));
    CHECK(0 < sign_of(m_strcmp("a", NULL, 1)));
    CHECK(0 > sign_of(m_strcmp(NULL, "a", 1)));

    // 不得改动入参内容
    {
        char a[] = "abc";
        char b[] = "abd";
        char a_copy[sizeof(a)];
        char b_copy[sizeof(b)];

        memcpy(a_copy, a, sizeof(a));
        memcpy(b_copy, b, sizeof(b));

        CHECK(0 > m_strcmp(a, b, 0));
        CHECK(0 == memcmp(a, a_copy, sizeof(a)));
        CHECK(0 == memcmp(b, b_copy, sizeof(b)));
    }

    // 与 libc strcmp 做差分对照（区分大小写）
    {
        static const char* const texts[] =
        {
            "", "a", "ab", "abc", "abd", "abcd", "zzz", "ZZZ", "aBc", "AbC",
        };
        size_t x;
        size_t y;

        for (x = 0; x < sizeof(texts) / sizeof(texts[0]); x++)
        {
            for (y = 0; y < sizeof(texts) / sizeof(texts[0]); y++)
            {
                CHECK(sign_of(strcmp(texts[x], texts[y])) == sign_of(m_strcmp(texts[x], texts[y], 1)));
            }
        }
    }
}

typedef struct
{
    const char* s1;
    const char* s2;
    unsigned long n;
    int cs;
    int sign;
} ncmp_case;

/*
 * 测试 m_strncmp：长度截断、大小写、NULL、n 为 0，并与 libc 差分对照。
*/
static void test_m_strncmp(void)
{
    static const ncmp_case cases[] =
    {
        {"abc", "abc", 0, 1, 0},
        {"abc", "abd", 1, 1, 0},
        {"abc", "abd", 2, 1, 0},
        {"abc", "abd", 3, 1, -1},
        {"abc", "abd", 100, 1, -1},
        {"abc", "abcd", 3, 1, 0},
        {"abc", "abcd", 4, 1, -1},
        {"abcd", "abc", 4, 1, 1},
        {"ABC", "abd", 2, 0, 0},
        {"ABC", "abd", 3, 0, -1},
        {"A", "a", 1, 0, 0},
        {"abC", "abc", 3, 0, 0},
        {"abcX", "abcY", 3, 1, 0},
        {"abcX", "abcY", 4, 1, -1},
        {"HeLLo", "hello", 10, 0, 0},
        {"HeLLo", "hellp", 10, 0, -1},
        {"abc", "ABC", 10, 2, 1},
        {"abc", "ABCD", 3, 1, 1},
        {"", "", 10, 1, 0},
        {"", "a", 10, 1, -1},
        {"a", "", 10, 1, 1},
        {"a", "abcdef", 1, 1, 0},
        {"abcdef", "a", 1, 1, 0},
        {"abcdef", "a", 100, 1, 1},
        {"a", "abcdef", 100, 1, -1},
        {"ab", "ab", 100, 0, 0},
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        const ncmp_case* c = &cases[i];

        expect_sign("m_strncmp", i, c->sign, m_strncmp(c->s1, c->s2, c->n, c->cs));
    }

    // NULL 与 n 为 0 的约定；n 为 0 时优先返回 0
    CHECK(0 == sign_of(m_strncmp(NULL, NULL, 5, 1)));
    CHECK(0 < sign_of(m_strncmp("a", NULL, 5, 1)));
    CHECK(0 > sign_of(m_strncmp(NULL, "a", 5, 1)));
    CHECK(0 == sign_of(m_strncmp(NULL, "a", 0, 1)));
    CHECK(0 == sign_of(m_strncmp(NULL, NULL, 0, 1)));

    // 不得改动入参内容
    {
        char a[] = "abcX";
        char b[] = "abcY";
        char a_copy[sizeof(a)];
        char b_copy[sizeof(b)];

        memcpy(a_copy, a, sizeof(a));
        memcpy(b_copy, b, sizeof(b));

        CHECK(0 == m_strncmp(a, b, 3, 0));
        CHECK(0 == memcmp(a, a_copy, sizeof(a)));
        CHECK(0 == memcmp(b, b_copy, sizeof(b)));
    }

    // 与 libc strncmp 做差分对照（区分大小写，覆盖多种长度）
    {
        static const char* const texts[] =
        {
            "", "a", "ab", "abc", "abd", "abcd", "abcdX", "zzz",
        };
        static unsigned long const lens[] = {0, 1, 2, 3, 5, 100};
        size_t x;
        size_t y;
        size_t z;

        for (x = 0; x < sizeof(texts) / sizeof(texts[0]); x++)
        {
            for (y = 0; y < sizeof(texts) / sizeof(texts[0]); y++)
            {
                for (z = 0; z < sizeof(lens) / sizeof(lens[0]); z++)
                {
                    CHECK(sign_of(strncmp(texts[x], texts[y], lens[z])) == sign_of(m_strncmp(texts[x], texts[y], lens[z], 1)));
                }
            }
        }
    }
}

/*
 * 测试 m_strtok_r：与 POSIX strtok_r 语义对齐。
 * 覆盖前导/连续/尾部分隔符、多字符分隔符集合、调用间更换 delim、空串、
 * 空分隔符集合、save_ptr 续接与异常入参；不依赖 libc 的 strtok_r。
*/
static void test_m_strtok_r(void)
{
    // 基本切分：token 内容、save_ptr 位置、分隔符被就地替换为 '\0'
    {
        char s[] = "a,b,c";
        char* save = NULL;

        char* t = m_strtok_r(s, ",", &save);
        CHECK(NULL != t);
        if (t)
            CHECK(0 == strcmp(t, "a"));
        CHECK(s + 2 == save);

        t = m_strtok_r(NULL, ",", &save);
        CHECK(NULL != t);
        if (t)
            CHECK(0 == strcmp(t, "b"));
        CHECK(s + 4 == save);

        t = m_strtok_r(NULL, ",", &save);
        CHECK(NULL != t);
        if (t)
            CHECK(0 == strcmp(t, "c"));
        CHECK(s + 5 == save);

        t = m_strtok_r(NULL, ",", &save);
        CHECK(NULL == t);
        CHECK(s + 5 == save);
    }

    // 前导、连续、尾部分隔符不产生空 token
    {
        char s[] = ",,a,,b,";
        char* save = NULL;

        char* t = m_strtok_r(s, ",", &save);
        CHECK(NULL != t);
        if (t)
            CHECK(0 == strcmp(t, "a"));
        CHECK(s + 4 == save);

        t = m_strtok_r(NULL, ",", &save);
        CHECK(NULL != t);
        if (t)
            CHECK(0 == strcmp(t, "b"));
        CHECK(s + 7 == save);

        CHECK(NULL == m_strtok_r(NULL, ",", &save));
    }

    // 只有分隔符：一次就返回 NULL，save_ptr 指向串尾
    {
        char s[] = ",,,";
        char* save = NULL;

        CHECK(NULL == m_strtok_r(s, ",", &save));
        CHECK(s + 3 == save);
    }

    // 空串：返回 NULL，save_ptr 仍指向串首 '\0'
    {
        char s[] = "";
        char* save = NULL;

        CHECK(NULL == m_strtok_r(s, ",", &save));
        CHECK(s == save);
    }

    // 多分隔符集合，且允许调用间更换 delim
    {
        char s[] = "a;b,c";
        char* save = NULL;

        char* t = m_strtok_r(s, ";", &save);
        CHECK(NULL != t);
        if (t)
            CHECK(0 == strcmp(t, "a"));

        t = m_strtok_r(NULL, ",", &save);
        CHECK(NULL != t);
        if (t)
            CHECK(0 == strcmp(t, "b"));

        t = m_strtok_r(NULL, ";,", &save);
        CHECK(NULL != t);
        if (t)
            CHECK(0 == strcmp(t, "c"));

        CHECK(NULL == m_strtok_r(NULL, ";,", &save));
    }

    // 空分隔符集合：整个字符串作为唯一 token
    {
        char s[] = "abc";
        char* save = NULL;

        char* t = m_strtok_r(s, "", &save);
        CHECK(NULL != t);
        if (t)
            CHECK(0 == strcmp(t, "abc"));
        CHECK(s + 3 == save);
        CHECK(NULL == m_strtok_r(NULL, "", &save));
    }

    // 异常入参：POSIX 未定义，本实现统一返回 NULL
    {
        char s[] = "a,b";
        char* save = NULL;

        CHECK(NULL == m_strtok_r(s, ",", NULL));
        CHECK(NULL == m_strtok_r(s, NULL, &save));
        CHECK(NULL == m_strtok_r(NULL, ",", &save));
    }
}

/*
 * 测试 m_memmem：长度化、二进制安全查找。
 * 覆盖命中偏移、大小写、未命中、空模式/空文本、含 '\0' 的数据。
*/
static void test_m_memmem(void)
{
    // 文本场景：与 libc strstr 对照定位 "\r\n\r\n"
    {
        char buf[] = "HTTP/1.1 200 OK\r\nA: 1\r\n\r\nbody";
        char* got = (char*)m_memmem(buf, (unsigned long)strlen(buf), "\r\n\r\n", 4, 1);

        CHECK(NULL != got);
        CHECK(strstr(buf, "\r\n\r\n") == got);
    }

    // 大小写敏感与不敏感
    {
        char buf[] = "Content-Length: 10";
        unsigned long len = (unsigned long)strlen(buf);

        CHECK(buf == (char*)m_memmem(buf, len, "content-length", 14, 0));
        CHECK(NULL == m_memmem(buf, len, "content-length", 14, 1));
    }

    // 忽略大小写时的 KMP 失配回退、重叠模式与单字符模式
    {
        char ci_text[] = "xxaAab";
        char overlap[] = "aaaa";
        char single[] = "abc";

        CHECK(ci_text + 3 == (char*)m_memmem(ci_text, 6, "Aab", 3, 0));
        CHECK(overlap + 0 == (char*)m_memmem(overlap, 4, "aaa", 3, 1));
        CHECK(single + 1 == (char*)m_memmem(single, 3, "b", 1, 1));
    }

    // 未命中、空模式、空文本、NULL
    CHECK(NULL == m_memmem("abc", 3, "abd", 3, 1));
    CHECK(NULL == m_memmem("abc", 3, "", 0, 1));
    CHECK(NULL == m_memmem("", 0, "a", 1, 1));
    CHECK(NULL == m_memmem(NULL, 0, "a", 1, 1));
    CHECK(NULL == m_memmem("a", 1, NULL, 1, 1));

    // 二进制数据：允许包含 '\0'，只在给定长度内查找
    {
        static const unsigned char bin[] = {0x00, 0x01, 0xAA, 0xBB, 0x00, 0xAA, 0xBB};
        static const unsigned char pat[] = {0xAA, 0xBB};
        static const unsigned char pat2[] = {0xBB, 0x00};

        CHECK((char*)bin + 2 == (char*)m_memmem(bin, sizeof(bin), pat, sizeof(pat), 1));
        CHECK((char*)bin + 3 == (char*)m_memmem(bin, sizeof(bin), pat2, sizeof(pat2), 1));
        CHECK(NULL == m_memmem(bin, 2, pat, sizeof(pat), 1));
    }

    // 与 m_strstr 的差异：m_strstr 遇 '\0' 截断，m_memmem 按长度查找
    {
        char embedded[] = "ab\0cd";
        char* got = (char*)m_memmem(embedded, 5, "cd", 2, 1);

        CHECK(NULL == m_strstr(embedded, "cd", 1));
        CHECK(NULL != got);
        CHECK(embedded + 3 == got);
    }

    // 长缓冲末尾命中
    {
        static char big[1024];
        char* got;

        memset(big, 'x', sizeof(big));
        memcpy(big + 1000, "needle", 6);

        got = (char*)m_memmem(big, sizeof(big), "needle", 6, 1);
        CHECK(NULL != got);
        CHECK(big + 1000 == got);
    }
}

/*
 * 测试 m_strdup：内容复制、地址独立、可写、空串与 NULL。
*/
static void test_m_strdup(void)
{
    // 正常复制：内容相等、地址不同、修改副本不影响源
    {
        char src[] = "hello";
        char* dup = m_strdup(src);

        CHECK(NULL != dup);
        if (dup)
        {
            CHECK(0 == strcmp(dup, src));
            CHECK(dup != src);
            dup[0] = 'H';
            CHECK(0 == strcmp(src, "hello"));
            CHECK(0 == strcmp(dup, "Hello"));
            m_free(dup);
        }
    }

    // 空串
    {
        char* dup = m_strdup("");

        CHECK(NULL != dup);
        if (dup)
        {
            CHECK('\0' == dup[0]);
            m_free(dup);
        }
    }

    // NULL 入参
    CHECK(NULL == m_strdup(NULL));

    // 较长内容
    {
        char src[256];
        char* dup;

        memset(src, 'a', sizeof(src) - 1);
        src[sizeof(src) - 1] = '\0';

        dup = m_strdup(src);
        CHECK(NULL != dup);
        if (dup)
        {
            CHECK(0 == strcmp(dup, src));
            m_free(dup);
        }
    }
}

/*
 * 测试 m_strndup：n 小于/等于/大于源长度、n 为 0、NULL 与副本独立性。
*/
static void test_m_strndup(void)
{
    // n 小于源长度
    {
        char* dup = m_strndup("hello", 2);

        CHECK(NULL != dup);
        if (dup)
        {
            CHECK(0 == strcmp(dup, "he"));
            m_free(dup);
        }
    }

    // n 等于源长度
    {
        char* dup = m_strndup("hello", 5);

        CHECK(NULL != dup);
        if (dup)
        {
            CHECK(0 == strcmp(dup, "hello"));
            m_free(dup);
        }
    }

    // n 大于源长度
    {
        char* dup = m_strndup("hi", 100);

        CHECK(NULL != dup);
        if (dup)
        {
            CHECK(0 == strcmp(dup, "hi"));
            m_free(dup);
        }
    }

    // n 为 0：返回空串
    {
        char* dup = m_strndup("hello", 0);

        CHECK(NULL != dup);
        if (dup)
        {
            CHECK('\0' == dup[0]);
            m_free(dup);
        }
    }

    // NULL 入参
    CHECK(NULL == m_strndup(NULL, 5));

    // 结果与源相互独立
    {
        char src[] = "abcdef";
        char* dup = m_strndup(src, 3);

        CHECK(NULL != dup);
        if (dup)
        {
            CHECK(0 == strcmp(dup, "abc"));
            dup[0] = 'X';
            CHECK(0 == strcmp(src, "abcdef"));
            m_free(dup);
        }
    }
}

/*
 * 测试 m_strnlen：上限大于/等于/小于实际长度、空串与 NULL。
*/
static void test_m_strnlen(void)
{
    char s[] = "hello";

    CHECK(5 == m_strnlen(s, 100));
    CHECK(5 == m_strnlen(s, 5));
    CHECK(3 == m_strnlen(s, 3));
    CHECK(0 == m_strnlen(s, 0));
    CHECK(0 == m_strnlen("", 10));
    CHECK(0 == m_strnlen(NULL, 10));

    CHECK((unsigned long)strlen(s) == m_strnlen(s, (unsigned long)strlen(s)));
}

/*
 * 测试 m_trim：首部/尾部/首尾去除、len 限定范围、多字符集合、
 * 全为待去除字符、空串、源串不被修改与异常入参。
*/
static void test_m_trim(void)
{
    // 首部去除
    {
        char* t = m_trim("  abc  ", 7, " ", 0);

        CHECK(NULL != t);
        if (t)
        {
            CHECK(0 == strcmp(t, "abc  "));
            m_free(t);
        }
    }

    // 尾部去除
    {
        char* t = m_trim("  abc  ", 7, " ", 1);

        CHECK(NULL != t);
        if (t)
        {
            CHECK(0 == strcmp(t, "  abc"));
            m_free(t);
        }
    }

    // 首尾去除
    {
        char* t = m_trim("  abc  ", 7, " ", 2);

        CHECK(NULL != t);
        if (t)
        {
            CHECK(0 == strcmp(t, "abc"));
            m_free(t);
        }
    }

    // pos 非 0/1 时按首尾处理
    {
        char* t = m_trim("  abc  ", 7, " ", 9);

        CHECK(NULL != t);
        if (t)
        {
            CHECK(0 == strcmp(t, "abc"));
            m_free(t);
        }
    }

    // 全部字符都在待去除集合中
    {
        char* t = m_trim("     ", 5, " ", 2);

        CHECK(NULL != t);
        if (t)
        {
            CHECK('\0' == t[0]);
            m_free(t);
        }
    }

    // 只处理前 len 个字符
    {
        char* t = m_trim("abcXYZ", 3, " ", 2);

        CHECK(NULL != t);
        if (t)
        {
            CHECK(0 == strcmp(t, "abc"));
            m_free(t);
        }
    }

    // 多字符集合（CRLF 与空白）
    {
        char* t = m_trim("\r\n abc \t", 8, " \t\r\n", 2);

        CHECK(NULL != t);
        if (t)
        {
            CHECK(0 == strcmp(t, "abc"));
            m_free(t);
        }
    }

    // 空串
    {
        char* t = m_trim("", 0, " ", 2);

        CHECK(NULL != t);
        if (t)
        {
            CHECK('\0' == t[0]);
            m_free(t);
        }
    }

    // 源串不被修改
    {
        char src[] = "  abc  ";
        char* t = m_trim(src, 7, " ", 2);

        CHECK(NULL != t);
        CHECK(0 == strcmp(src, "  abc  "));
        if (t)
            m_free(t);
    }

    // len 落在待去除区段内时的首部/尾部边界
    {
        char* t = m_trim("   abc", 3, " ", 0);

        CHECK(NULL != t);
        if (t)
        {
            CHECK('\0' == t[0]);
            m_free(t);
        }
    }
    {
        char* t = m_trim("abc   ", 6, " ", 1);

        CHECK(NULL != t);
        if (t)
        {
            CHECK(0 == strcmp(t, "abc"));
            m_free(t);
        }
    }

    // 异常入参
    CHECK(NULL == m_trim(NULL, 3, " ", 2));
    CHECK(NULL == m_trim("abc", 3, NULL, 2));
    CHECK(NULL == m_trim("abc", -1, " ", 2));
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    test_m_malloc_free();
    test_m_strstr();
    test_m_memmem();
    test_m_strcmp();
    test_m_strncmp();
    test_m_strdup();
    test_m_strndup();
    test_m_strnlen();
    test_m_strtok_r();
    test_m_trim();

    printf("m_test: %d passed, %d failed\n", g_passed, g_failed);

    return g_failed ? 1 : 0;
}

