/*
 * domain/validation.c — các rule kiểm tra input thuần, không phụ thuộc hạ tầng.
 *
 * File này chỉ dùng thư viện C chuẩn, không include MySQL/OpenSSL/socket. Mục
 * đích là tách các rule dễ test như username, email, kích thước message và
 * prefix E2EE khỏi phần network/database phức tạp của server.
 */

#include "validation.h"

#include <string.h>
#include <ctype.h>

/* Username nội bộ: chỉ cho chữ/số/_ để tránh ký tự khó escape ở UI/log. */

int domain_validate_username(const char *username)
{
    if (!username) return 0;
    size_t n = strlen(username);
    if (n < 3 || n > 63) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)username[i];
        if (!isalnum(c) && c != '_') return 0;
    }
    return 1;
}

/* Email optional khi đăng ký, nhưng nếu có thì phải có dạng cơ bản local@domain. */

int domain_validate_email(const char *email)
{
    /* Rỗng/NULL là hợp lệ vì email là field optional khi đăng ký. */
    if (!email || email[0] == '\0') return 1;

    size_t n = strlen(email);
    if (n > 254) return 0;

    /* Phải có '@' và phần local không được rỗng. */
    const char *at = strchr(email, '@');
    if (!at || at == email) return 0;

    /* Domain cần có ít nhất một dấu '.' và còn ký tự sau dấu đó. */
    const char *dot = strchr(at + 1, '.');
    if (!dot || *(dot + 1) == '\0') return 0;

    return 1;
}

/* Tên group không rỗng và giới hạn độ dài để tránh layout/log quá lớn. */

int domain_validate_group_name(const char *name)
{
    if (!name) return 0;
    size_t n = strlen(name);
    return (n >= 1 && n <= 100);
}

/* Body message ở server là ciphertext, nhưng vẫn cần giới hạn rỗng/quá lớn. */

int domain_validate_message_body(const char *body, size_t max_len)
{
    if (!body || body[0] == '\0') return 0;
    return (strlen(body) <= max_len);
}

/* Role group hiện chỉ có admin/member. */

int domain_validate_role(const char *role)
{
    if (!role) return 0;
    return (strcmp(role, "admin") == 0 || strcmp(role, "member") == 0);
}

/* Display name optional, giới hạn để profile/inbox không bị phá layout. */

int domain_validate_display_name(const char *name)
{
    if (!name || name[0] == '\0') return 1;
    return (strlen(name) <= 64);
}

/* Bio optional, giới hạn độ dài trước khi lưu DB. */

int domain_validate_bio(const char *bio)
{
    if (!bio || bio[0] == '\0') return 1;
    return (strlen(bio) <= 512);
}

/* Reaction emoji là text ngắn; giới hạn byte để tránh abuse payload. */

int domain_validate_emoji(const char *emoji)
{
    if (!emoji || emoji[0] == '\0') return 0;
    return (strlen(emoji) <= 32);
}

/* Prefix E2EE cho body message. */

/*
 * Prefix SecChat hợp lệ:
 *   S3PQI:<b64-json> — message khởi tạo DM bằng hybrid PQXDH
 *   S3DR:<b64-json>  — message DM sau khi vào Double Ratchet
 *   S3MLS:<b64-json> — message/control group theo MLS application layer
 *
 * Các prefix cũ (__KEM_INIT__, E2E, E2R, E2RK, E2GS) bị từ chối có chủ đích
 * sau khi chuyển sang wire S3. Server không giải mã body, nhưng việc chặn prefix cũ
 * giúp phát hiện client lỗi hoặc test cũ đang gửi format không còn hỗ trợ.
 */
int domain_validate_e2e_prefix(const char *body)
{
    if (!body) return 0;
    if (strncmp(body, "S3PQI:", 6) == 0) return 1;
    if (strncmp(body, "S3DR:",  5) == 0) return 1;
    if (strncmp(body, "S3MLS:", 6) == 0) return 1;
    return 0;
}

/* Password hash client gửi lên là hex SHA-256 64 ký tự. */

int domain_validate_pwhash(const char *pwhash)
{
    if (!pwhash) return 0;
    size_t n = strlen(pwhash);
    if (n != 64) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)pwhash[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) {
            return 0;
        }
    }
    return 1;
}
