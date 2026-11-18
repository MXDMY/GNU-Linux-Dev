/*
 * 跨平台的算法、数据结构或其它公共函数等，
 * 用于解决某些平台默认的 C 库无法满足需求的情况，
 * 包括但不限于以下情况（以 C99 为基准）：
 * - 默认的 malloc 可分配的堆内存过小；
 * - 缺少的函数或标准函数不满足要求；
 * - 某些函数需要特殊平台、扩展或更高版本的 C 标准才提供；
*/

#ifndef M_2026_H
#define M_2026_H

#ifdef __cplusplus
extern "C" {
#endif

extern void* m_malloc(unsigned long size);

extern void m_free(void* ptr);

extern char* m_strstr(const char* haystack, const char* needle, int cs);

extern void* m_memmem(const void* haystack, unsigned long haystacklen
                    , const void* needle, unsigned long needlelen, int cs);

extern int m_strcmp(const char* s1, const char* s2, int cs);

extern int m_strncmp(const char* s1, const char* s2, unsigned long n, int cs);

extern char* m_strdup(const char* s);

extern char* m_strndup(const char* string, unsigned long n);

extern unsigned long m_strnlen(const char* s, unsigned long maxlen);

/*
 * 按分隔符集合切分字符串，语义与 POSIX strtok_r 对齐。
 * 首次调用 s 传待切分的可写字符串，之后 s 传 NULL，由 save_ptr 续接；切分
 * 过程会把 token 末尾的分隔符就地改为 '\0'，因此 s 的内容会被修改。
 * @param s        待切分字符串；NULL 表示从 save_ptr 的位置继续
 * @param delim    分隔符集合，每次调用可以不同
 * @param save_ptr 保存调用之间的位置，不能为 NULL
 * @return         下一个 token 的首地址；没有更多 token 时返回 NULL
 * @note           连续分隔符不产生空 token；没有 token 时 save_ptr 指向串尾 '\0'
*/
extern char* m_strtok_r(char* s, const char* delim, char** save_ptr);

/*
 * 去除头部、尾部指定连续字符，示例：
 * ```c
 * char* s = " \n1hello, world\t\r";
 * char* sub = m_trim(s, " \n1\t\r", 2); // "hello, world"
 * ```
 * @param s     待去除字符串
 * @param cset  要去除的字符合集
 * @param pos   0 首部；1 尾部；2 首尾
 * @return      去除后的字符串，m_malloc 分配
*/
extern char* m_trim(const char* s, const char* cset, int pos);

#ifdef __cplusplus
}
#endif

#endif
