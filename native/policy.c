#define _DARWIN_C_SOURCE

#include "policy.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/acl.h>
#endif

#define MOC_POLICY_MAX_SIZE 65536u

struct parse_state {
    int schema;
    int digest;
    int gateway;
    int servercert;
    int login_path;
    int final_path;
    int token_cookie;
    int dns_rule_count;
    int dns_domain[MOC_MAX_DNS_RULES];
    int dns_server_count[MOC_MAX_DNS_RULES];
    int dns_server[MOC_MAX_DNS_RULES][MOC_MAX_DNS_SERVERS];
};

enum dns_key_kind {
    DNS_KEY_INVALID,
    DNS_KEY_DOMAIN,
    DNS_KEY_SERVER_COUNT,
    DNS_KEY_SERVER,
};

static int is_printable_ascii(const char *value)
{
    if (value == NULL || *value == '\0')
        return 0;
    for (; *value != '\0'; value++) {
        unsigned char byte = (unsigned char)*value;
        if (byte < 0x21 || byte > 0x7e)
            return 0;
    }
    return 1;
}

static int copy_value(char *output, size_t output_size, const char *value)
{
    size_t length;

    if (!is_printable_ascii(value))
        return -1;
    length = strlen(value);
    if (length >= output_size)
        return -1;
    memcpy(output, value, length + 1);
    return 0;
}

static int is_lower_hex(const char *value, size_t length)
{
    for (size_t index = 0; index < length; index++) {
        if (!((value[index] >= '0' && value[index] <= '9') ||
                (value[index] >= 'a' && value[index] <= 'f')))
            return 0;
    }
    return 1;
}

static int is_hex(const char *value, size_t length)
{
    for (size_t index = 0; index < length; index++) {
        char byte = value[index];
        if (!((byte >= '0' && byte <= '9') || (byte >= 'a' && byte <= 'f') ||
                (byte >= 'A' && byte <= 'F')))
            return 0;
    }
    return 1;
}

static int digest_is_valid(const char *value)
{
    static const char prefix[] = "sha256:";

    return strlen(value) == (sizeof(prefix) - 1) + 64 &&
        strncmp(value, prefix, sizeof(prefix) - 1) == 0 &&
        is_lower_hex(value + sizeof(prefix) - 1, 64);
}

static int hostname_is_valid(const char *value)
{
    size_t length;
    size_t label_length = 0;
    int has_dot = 0;

    if (!is_printable_ascii(value))
        return 0;
    length = strlen(value);
    if (length == 0 || length > 253 || value[length - 1] == '.')
        return 0;
    for (size_t index = 0; index < length; index++) {
        char byte = value[index];
        if (byte == '.') {
            if (label_length == 0 || label_length > 63 || value[index - 1] == '-')
                return 0;
            label_length = 0;
            has_dot = 1;
            continue;
        }
        if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
                (byte == '-' && label_length > 0)))
            return 0;
        label_length++;
    }
    return has_dot && label_length > 0 && label_length <= 63 &&
        value[length - 1] != '-';
}

static int path_is_valid(const char *value)
{
    const char *segment;

    if (!is_printable_ascii(value) || value[0] != '/' || value[1] == '/' ||
        strchr(value, '\\') != NULL || strchr(value, '?') != NULL ||
        strchr(value, '#') != NULL || strchr(value, '%') != NULL ||
        strstr(value, "//") != NULL)
        return 0;
    segment = value + 1;
    while (*segment != '\0') {
        const char *end = strchr(segment, '/');
        size_t length = end == NULL ? strlen(segment) : (size_t)(end - segment);
        if ((length == 1 && segment[0] == '.') ||
            (length == 2 && segment[0] == '.' && segment[1] == '.'))
            return 0;
        if (end == NULL)
            break;
        segment = end + 1;
    }
    return 1;
}

static int cookie_name_is_valid(const char *value)
{
    static const char allowed_punctuation[] = "!#$%&'*+-.^_`|~";

    if (!is_printable_ascii(value) || strlen(value) >= 128)
        return 0;
    for (; *value != '\0'; value++) {
        if (!((*value >= 'A' && *value <= 'Z') || (*value >= 'a' && *value <= 'z') ||
                (*value >= '0' && *value <= '9') ||
                strchr(allowed_punctuation, *value) != NULL))
            return 0;
    }
    return 1;
}

static int base64_is_valid(const char *value)
{
    size_t length = strlen(value);
    size_t padding = 0;

    if (length == 0 || length % 4 != 0)
        return 0;
    while (padding < 2 && length > padding && value[length - padding - 1] == '=')
        padding++;
    for (size_t index = 0; index < length - padding; index++) {
        char byte = value[index];
        if (!((byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                (byte >= '0' && byte <= '9') || byte == '+' || byte == '/'))
            return 0;
    }
    for (size_t index = length - padding; index < length; index++) {
        if (value[index] != '=')
            return 0;
    }
    return strchr(value, '=') == NULL ||
        (size_t)(strchr(value, '=') - value) == length - padding;
}

static int base64_character_value(char value)
{
    if (value >= 'A' && value <= 'Z')
        return value - 'A';
    if (value >= 'a' && value <= 'z')
        return value - 'a' + 26;
    if (value >= '0' && value <= '9')
        return value - '0' + 52;
    if (value == '+')
        return 62;
    if (value == '/')
        return 63;
    return -1;
}

static int spki_pin_is_valid(const char *value)
{
    size_t length = strlen(value);

    return length == 44 && value[43] == '=' &&
        base64_is_valid(value) &&
        (base64_character_value(value[42]) & 0x03) == 0;
}

static int servercert_is_valid(const char *value)
{
    if (strncmp(value, "sha1:", 5) == 0)
        return strlen(value + 5) == 40 && is_hex(value + 5, 40);
    if (strncmp(value, "sha256:", 7) == 0)
        return strlen(value + 7) == 64 && is_hex(value + 7, 64);
    if (strncmp(value, "pin-sha256:", 11) == 0)
        return spki_pin_is_valid(value + 11);
    return 0;
}

static int ip_address_is_valid(const char *value)
{
    unsigned char output[sizeof(struct in6_addr)];

    return inet_pton(AF_INET, value, output) == 1 ||
        inet_pton(AF_INET6, value, output) == 1;
}

static int parse_count(const char *value, size_t maximum, size_t *output)
{
    size_t parsed = 0;

    if (value == NULL || *value == '\0' ||
        (value[0] == '0' && value[1] != '\0'))
        return -1;
    for (; *value != '\0'; value++) {
        if (*value < '0' || *value > '9')
            return -1;
        size_t digit = (size_t)(*value - '0');

        if (digit > maximum || parsed > (maximum - digit) / 10)
            return -1;
        parsed = parsed * 10 + digit;
    }
    if (parsed > maximum)
        return -1;
    *output = parsed;
    return 0;
}

static enum dns_key_kind parse_dns_key(
    const char *key, size_t *rule_index, size_t *server_index)
{
    const char *cursor;
    size_t rule = 0;
    size_t server = 0;

    if (strncmp(key, "DNS_", 4) != 0)
        return DNS_KEY_INVALID;
    cursor = key + 4;
    if (*cursor < '0' || *cursor > '9' ||
        (*cursor == '0' && cursor[1] >= '0' && cursor[1] <= '9'))
        return DNS_KEY_INVALID;
    while (*cursor >= '0' && *cursor <= '9') {
        if (rule > MOC_MAX_DNS_RULES)
            return DNS_KEY_INVALID;
        rule = rule * 10 + (size_t)(*cursor - '0');
        cursor++;
    }
    if (rule >= MOC_MAX_DNS_RULES)
        return DNS_KEY_INVALID;
    *rule_index = rule;
    if (strcmp(cursor, "_DOMAIN") == 0)
        return DNS_KEY_DOMAIN;
    if (strcmp(cursor, "_SERVER_COUNT") == 0)
        return DNS_KEY_SERVER_COUNT;
    if (strncmp(cursor, "_SERVER_", 8) != 0)
        return DNS_KEY_INVALID;
    cursor += 8;
    if (*cursor < '0' || *cursor > '9' ||
        (*cursor == '0' && cursor[1] != '\0'))
        return DNS_KEY_INVALID;
    while (*cursor >= '0' && *cursor <= '9') {
        size_t digit = (size_t)(*cursor - '0');

        if (digit >= MOC_MAX_DNS_SERVERS ||
            server > ((MOC_MAX_DNS_SERVERS - 1) - digit) / 10)
            return DNS_KEY_INVALID;
        server = server * 10 + digit;
        cursor++;
    }
    if (*cursor != '\0' || server >= MOC_MAX_DNS_SERVERS)
        return DNS_KEY_INVALID;
    *server_index = server;
    return DNS_KEY_SERVER;
}

static int parse_fixed_key(
    const char *key, const char *value, struct moc_policy *policy,
    struct parse_state *state)
{
    if (strcmp(key, "SCHEMA") == 0) {
        if (state->schema || strcmp(value, "1") != 0)
            return -1;
        state->schema = 1;
        return 0;
    }
    if (strcmp(key, "DIGEST") == 0) {
        if (state->digest || !digest_is_valid(value) ||
            copy_value(policy->digest, sizeof(policy->digest), value) != 0)
            return -1;
        state->digest = 1;
        return 0;
    }
    if (strcmp(key, "GATEWAY") == 0) {
        if (state->gateway || !hostname_is_valid(value) ||
            copy_value(policy->gateway, sizeof(policy->gateway), value) != 0)
            return -1;
        state->gateway = 1;
        return 0;
    }
    if (strcmp(key, "SERVERCERT") == 0) {
        if (state->servercert || !servercert_is_valid(value) ||
            copy_value(policy->servercert, sizeof(policy->servercert), value) != 0)
            return -1;
        state->servercert = 1;
        return 0;
    }
    if (strcmp(key, "LOGIN_PATH") == 0) {
        if (state->login_path || !path_is_valid(value) ||
            copy_value(policy->login_path, sizeof(policy->login_path), value) != 0)
            return -1;
        state->login_path = 1;
        return 0;
    }
    if (strcmp(key, "FINAL_PATH") == 0) {
        if (state->final_path || !path_is_valid(value) ||
            copy_value(policy->final_path, sizeof(policy->final_path), value) != 0)
            return -1;
        state->final_path = 1;
        return 0;
    }
    if (strcmp(key, "TOKEN_COOKIE") == 0) {
        if (state->token_cookie || !cookie_name_is_valid(value) ||
            copy_value(policy->token_cookie, sizeof(policy->token_cookie), value) != 0)
            return -1;
        state->token_cookie = 1;
        return 0;
    }
    if (strcmp(key, "DNS_RULE_COUNT") == 0) {
        if (state->dns_rule_count ||
            parse_count(value, MOC_MAX_DNS_RULES, &policy->dns_rule_count) != 0)
            return -1;
        state->dns_rule_count = 1;
        return 0;
    }
    return 1;
}

static int parse_dns_entry(
    const char *key, const char *value, struct moc_policy *policy,
    struct parse_state *state)
{
    size_t rule_index = 0;
    size_t server_index = 0;
    enum dns_key_kind kind = parse_dns_key(key, &rule_index, &server_index);

    if (kind == DNS_KEY_DOMAIN) {
        if (state->dns_domain[rule_index] || !hostname_is_valid(value) ||
            copy_value(policy->dns_rules[rule_index].domain,
                sizeof(policy->dns_rules[rule_index].domain), value) != 0)
            return -1;
        state->dns_domain[rule_index] = 1;
        return 0;
    }
    if (kind == DNS_KEY_SERVER_COUNT) {
        if (state->dns_server_count[rule_index] ||
            parse_count(value, MOC_MAX_DNS_SERVERS,
                &policy->dns_rules[rule_index].nameserver_count) != 0 ||
            policy->dns_rules[rule_index].nameserver_count == 0)
            return -1;
        state->dns_server_count[rule_index] = 1;
        return 0;
    }
    if (kind == DNS_KEY_SERVER) {
        if (state->dns_server[rule_index][server_index] ||
            !ip_address_is_valid(value) ||
            copy_value(policy->dns_rules[rule_index].nameservers[server_index],
                sizeof(policy->dns_rules[rule_index].nameservers[server_index]),
                value) != 0)
            return -1;
        state->dns_server[rule_index][server_index] = 1;
        return 0;
    }
    return -1;
}

static int parse_line(
    char *line, struct moc_policy *policy, struct parse_state *state)
{
    char *separator;
    int fixed_result;

    if (*line == '\0' || !is_printable_ascii(line))
        return -1;
    separator = strchr(line, '=');
    if (separator == NULL || separator == line || separator[1] == '\0')
        return -1;
    *separator = '\0';
    fixed_result = parse_fixed_key(line, separator + 1, policy, state);
    if (fixed_result <= 0)
        return fixed_result;
    return parse_dns_entry(line, separator + 1, policy, state);
}

static int policy_is_complete(
    const struct moc_policy *policy, const struct parse_state *state)
{
    if (!state->schema || !state->digest || !state->gateway || !state->servercert ||
        !state->login_path || !state->final_path || !state->token_cookie ||
        !state->dns_rule_count)
        return 0;
    for (size_t rule = 0; rule < MOC_MAX_DNS_RULES; rule++) {
        int expected_rule = rule < policy->dns_rule_count;
        if (state->dns_domain[rule] != expected_rule ||
            state->dns_server_count[rule] != expected_rule)
            return 0;
        for (size_t server = 0; server < MOC_MAX_DNS_SERVERS; server++) {
            int expected_server = expected_rule &&
                server < policy->dns_rules[rule].nameserver_count;
            if (state->dns_server[rule][server] != expected_server)
                return 0;
        }
    }
    return 1;
}

void moc_policy_clear(struct moc_policy *policy)
{
    volatile unsigned char *bytes;

    if (policy == NULL)
        return;
    bytes = (volatile unsigned char *)policy;
    for (size_t index = 0; index < sizeof(*policy); index++)
        bytes[index] = 0;
}

int moc_policy_parse(const char *text, size_t length, struct moc_policy *policy)
{
    struct parse_state state = {0};
    char *buffer;
    char *cursor;
    char *end;
    int result = -1;

    if (policy == NULL)
        return -1;
    moc_policy_clear(policy);
    if (text == NULL || length == 0 || length > MOC_POLICY_MAX_SIZE ||
        text[length - 1] != '\n' || memchr(text, '\0', length) != NULL)
        return -1;
    buffer = malloc(length + 1);
    if (buffer == NULL)
        return -1;
    memcpy(buffer, text, length);
    buffer[length] = '\0';
    cursor = buffer;
    end = buffer + length;
    while (cursor < end) {
        char *newline = strchr(cursor, '\n');
        if (newline == NULL)
            goto cleanup;
        *newline = '\0';
        if (parse_line(cursor, policy, &state) != 0)
            goto cleanup;
        cursor = newline + 1;
    }
    if (!policy_is_complete(policy, &state))
        goto cleanup;
    result = 0;

cleanup:
    memset(buffer, 0, length + 1);
    free(buffer);
    if (result != 0)
        moc_policy_clear(policy);
    return result;
}

int moc_policy_metadata_is_safe(uid_t owner, mode_t mode, off_t size)
{
    return owner == 0 && S_ISREG(mode) && (mode & (S_IWGRP | S_IWOTH)) == 0 &&
        size >= 1 && size <= (off_t)MOC_POLICY_MAX_SIZE;
}

int moc_policy_fd_acl_is_safe(int fd)
{
#ifdef __APPLE__
    acl_entry_t entry;
    acl_t acl;
    int has_entry;
    int free_result;

    errno = 0;
    acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (acl == NULL)
        return errno == ENOENT;
    has_entry = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry) == 0;
    free_result = acl_free(acl);
    return !has_entry && free_result == 0;
#else
    (void)fd;
    return 1;
#endif
}

int moc_policy_load(const char *path, struct moc_policy *policy)
{
    struct stat info;
    char *buffer = NULL;
    size_t offset = 0;
    int fd = -1;
    int result = -1;

    if (policy == NULL)
        return -1;
    moc_policy_clear(policy);
    if (path == NULL)
        return -1;
    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || fstat(fd, &info) != 0 ||
        !moc_policy_metadata_is_safe(info.st_uid, info.st_mode, info.st_size) ||
        !moc_policy_fd_acl_is_safe(fd))
        goto cleanup;
    buffer = malloc((size_t)info.st_size);
    if (buffer == NULL)
        goto cleanup;
    while (offset < (size_t)info.st_size) {
        ssize_t count = read(fd, buffer + offset, (size_t)info.st_size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto cleanup;
        offset += (size_t)count;
    }
    if (close(fd) != 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    result = moc_policy_parse(buffer, offset, policy);

cleanup:
    if (fd >= 0)
        (void)close(fd);
    if (buffer != NULL) {
        volatile unsigned char *bytes = (volatile unsigned char *)buffer;
        for (size_t index = 0; index < offset; index++)
            bytes[index] = 0;
        free(buffer);
    }
    if (result != 0)
        moc_policy_clear(policy);
    return result;
}

static int policy_url(
    const struct moc_policy *policy, const char *path, char *output, size_t size)
{
    int length;

    if (policy == NULL || path == NULL)
        return -1;
    length = snprintf(output, size, "https://%s%s", policy->gateway, path);
    return length > 0 && (size_t)length < size ? 0 : -1;
}

int moc_uri_is_allowed(const struct moc_policy *policy, const char *uri)
{
    char allowed[520];
    size_t prefix_length;

    if (policy_url(policy, policy == NULL ? NULL : policy->login_path, allowed,
            sizeof(allowed)) != 0)
        return 0;
    prefix_length = strlen(allowed);
    if (!is_printable_ascii(uri) || strchr(uri, '@') != NULL ||
        strchr(uri, '#') != NULL || strchr(uri, '\\') != NULL ||
        strncmp(uri, allowed, prefix_length) != 0)
        return 0;
    return uri[prefix_length] == '\0' || uri[prefix_length] == '?';
}

int moc_final_uri_is_allowed(const struct moc_policy *policy, const char *uri)
{
    char allowed[520];

    return policy_url(policy, policy == NULL ? NULL : policy->final_path, allowed,
               sizeof(allowed)) == 0 &&
        uri != NULL && strcmp(uri, allowed) == 0;
}

int moc_form_is_browser_only(const struct oc_auth_form *form)
{
    const struct oc_form_opt *option;

    if (form == NULL)
        return 0;
    for (option = form->opts; option != NULL; option = option->next) {
        if (option->type != OC_FORM_OPT_HIDDEN &&
            option->type != OC_FORM_OPT_SSO_TOKEN &&
            option->type != OC_FORM_OPT_SSO_USER)
            return 0;
    }
    return 1;
}
