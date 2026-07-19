#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "policy.h"

#define VALID_SERVERCERT "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

static const char VALID_POLICY[] =
    "SCHEMA=1\n"
    "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
    "GATEWAY=vpn.example.com\n"
    "SERVERCERT=" VALID_SERVERCERT "\n"
    "LOGIN_PATH=/saml/sp/login\n"
    "FINAL_PATH=/saml/sp/login_final\n"
    "TOKEN_COOKIE=acSamlv2Token\n"
    "DNS_RULE_COUNT=1\n"
    "DNS_0_DOMAIN=internal.example.com\n"
    "DNS_0_SERVER_COUNT=1\n"
    "DNS_0_SERVER_0=192.0.2.53\n";

static void assert_rejected(const char *text)
{
    struct moc_policy policy;

    memset(&policy, 0xa5, sizeof(policy));
    assert(moc_policy_parse(text, strlen(text), &policy) != 0);
    for (size_t index = 0; index < sizeof(policy); index++)
        assert(((const unsigned char *)&policy)[index] == 0);
}

static void test_parse_valid_policy(void)
{
    struct moc_policy policy = {0};

    assert(moc_policy_parse(VALID_POLICY, sizeof(VALID_POLICY) - 1, &policy) == 0);
    assert(strcmp(policy.digest,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000") == 0);
    assert(strcmp(policy.gateway, "vpn.example.com") == 0);
    assert(strcmp(policy.servercert, VALID_SERVERCERT) == 0);
    assert(strcmp(policy.login_path, "/saml/sp/login") == 0);
    assert(strcmp(policy.final_path, "/saml/sp/login_final") == 0);
    assert(strcmp(policy.token_cookie, "acSamlv2Token") == 0);
    assert(policy.dns_rule_count == 1);
    assert(strcmp(policy.dns_rules[0].domain, "internal.example.com") == 0);
    assert(policy.dns_rules[0].nameserver_count == 1);
    assert(strcmp(policy.dns_rules[0].nameservers[0], "192.0.2.53") == 0);
    moc_policy_clear(&policy);
}

static void test_rejects_missing_duplicate_and_unknown_keys(void)
{
    static const char missing[] =
        "SCHEMA=1\n"
        "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "GATEWAY=vpn.example.com\n";
    static const char duplicate[] =
        "SCHEMA=1\n"
        "SCHEMA=1\n"
        "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "GATEWAY=vpn.example.com\n"
        "SERVERCERT=" VALID_SERVERCERT "\n"
        "LOGIN_PATH=/saml/sp/login\n"
        "FINAL_PATH=/saml/sp/login_final\n"
        "TOKEN_COOKIE=acSamlv2Token\n"
        "DNS_RULE_COUNT=0\n";
    static const char unknown[] =
        "SCHEMA=1\n"
        "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "GATEWAY=vpn.example.com\n"
        "SERVERCERT=" VALID_SERVERCERT "\n"
        "LOGIN_PATH=/saml/sp/login\n"
        "FINAL_PATH=/saml/sp/login_final\n"
        "TOKEN_COOKIE=acSamlv2Token\n"
        "DNS_RULE_COUNT=0\n"
        "EXTRA=value\n";

    assert_rejected(missing);
    assert_rejected(duplicate);
    assert_rejected(unknown);
}

static void test_rejects_invalid_counts_addresses_paths_and_digests(void)
{
    static const char invalid_count[] =
        "SCHEMA=1\n"
        "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "GATEWAY=vpn.example.com\n"
        "SERVERCERT=" VALID_SERVERCERT "\n"
        "LOGIN_PATH=/saml/sp/login\n"
        "FINAL_PATH=/saml/sp/login_final\n"
        "TOKEN_COOKIE=acSamlv2Token\n"
        "DNS_RULE_COUNT=17\n";
    static const char invalid_ip[] =
        "SCHEMA=1\n"
        "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "GATEWAY=vpn.example.com\n"
        "SERVERCERT=" VALID_SERVERCERT "\n"
        "LOGIN_PATH=/saml/sp/login\n"
        "FINAL_PATH=/saml/sp/login_final\n"
        "TOKEN_COOKIE=acSamlv2Token\n"
        "DNS_RULE_COUNT=1\n"
        "DNS_0_DOMAIN=internal.example.com\n"
        "DNS_0_SERVER_COUNT=1\n"
        "DNS_0_SERVER_0=resolver.example.com\n";
    static const char invalid_path[] =
        "SCHEMA=1\n"
        "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "GATEWAY=vpn.example.com\n"
        "SERVERCERT=" VALID_SERVERCERT "\n"
        "LOGIN_PATH=/saml/../login\n"
        "FINAL_PATH=/saml/sp/login_final\n"
        "TOKEN_COOKIE=acSamlv2Token\n"
        "DNS_RULE_COUNT=0\n";
    static const char invalid_digest[] =
        "SCHEMA=1\n"
        "DIGEST=sha256:ABC\n"
        "GATEWAY=vpn.example.com\n"
        "SERVERCERT=" VALID_SERVERCERT "\n"
        "LOGIN_PATH=/saml/sp/login\n"
        "FINAL_PATH=/saml/sp/login_final\n"
        "TOKEN_COOKIE=acSamlv2Token\n"
        "DNS_RULE_COUNT=0\n";
    static const char wrapped_server_index[] =
        "SCHEMA=1\n"
        "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "GATEWAY=vpn.example.com\n"
        "SERVERCERT=" VALID_SERVERCERT "\n"
        "LOGIN_PATH=/saml/sp/login\n"
        "FINAL_PATH=/saml/sp/login_final\n"
        "TOKEN_COOKIE=acSamlv2Token\n"
        "DNS_RULE_COUNT=1\n"
        "DNS_0_DOMAIN=internal.example.com\n"
        "DNS_0_SERVER_COUNT=1\n"
        "DNS_0_SERVER_18446744073709551616=192.0.2.53\n";

    assert_rejected(invalid_count);
    assert_rejected(invalid_ip);
    assert_rejected(invalid_path);
    assert_rejected(invalid_digest);
    assert_rejected(wrapped_server_index);
}

static void test_accepts_canonical_and_rejects_truncated_spki_pins(void)
{
    char valid_nonzero_final_sextet[sizeof(VALID_POLICY)];
    char noncanonical_low_bits[sizeof(VALID_POLICY)];
    static const char truncated[] =
        "SCHEMA=1\n"
        "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "GATEWAY=vpn.example.com\n"
        "SERVERCERT=pin-sha256:dGVzdA==\n"
        "LOGIN_PATH=/saml/sp/login\n"
        "FINAL_PATH=/saml/sp/login_final\n"
        "TOKEN_COOKIE=acSamlv2Token\n"
        "DNS_RULE_COUNT=0\n";
    static const char invalid_padding_bits[] =
        "SCHEMA=1\n"
        "DIGEST=sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        "GATEWAY=vpn.example.com\n"
        "SERVERCERT=pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=\n"
        "LOGIN_PATH=/saml/sp/login\n"
        "FINAL_PATH=/saml/sp/login_final\n"
        "TOKEN_COOKIE=acSamlv2Token\n"
        "DNS_RULE_COUNT=0\n";

    assert_rejected(truncated);
    assert_rejected(invalid_padding_bits);
    memcpy(valid_nonzero_final_sextet, VALID_POLICY, sizeof(VALID_POLICY));
    char *valid_pin_padding = strstr(
        valid_nonzero_final_sextet, "=\nLOGIN_PATH");
    assert(valid_pin_padding != NULL);
    valid_pin_padding[-1] = 'E';
    struct moc_policy policy = {0};
    assert(moc_policy_parse(valid_nonzero_final_sextet,
        strlen(valid_nonzero_final_sextet), &policy) == 0);
    moc_policy_clear(&policy);
    memcpy(noncanonical_low_bits, VALID_POLICY, sizeof(VALID_POLICY));
    char *pin_padding = strstr(noncanonical_low_bits, "=\nLOGIN_PATH");
    assert(pin_padding != NULL);
    pin_padding[-1] = 'B';
    assert_rejected(noncanonical_low_bits);
}

#ifdef __APPLE__
int moc_policy_fd_acl_is_safe(int fd);

static void test_rejects_extended_acl(void)
{
    char target[] = "/tmp/meraki-openconnect-policy-acl.XXXXXX";
    pid_t child;
    int status = 0;
    int fd = mkstemp(target);

    assert(fd >= 0);
    assert(moc_policy_fd_acl_is_safe(fd));
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        execl("/bin/chmod", "chmod", "+a", "everyone deny write", target,
            (char *)NULL);
        _exit(127);
    }
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(!moc_policy_fd_acl_is_safe(fd));
    assert(close(fd) == 0);
    assert(unlink(target) == 0);
}
#endif

static void test_requires_final_newline(void)
{
    char text[sizeof(VALID_POLICY)];

    memcpy(text, VALID_POLICY, sizeof(VALID_POLICY));
    text[sizeof(VALID_POLICY) - 2] = '\0';
    assert_rejected(text);
}

static void test_clear_zeroes_all_policy_bytes(void)
{
    struct moc_policy policy;

    assert(moc_policy_parse(VALID_POLICY, sizeof(VALID_POLICY) - 1, &policy) == 0);
    moc_policy_clear(&policy);
    for (size_t index = 0; index < sizeof(policy); index++)
        assert(((const unsigned char *)&policy)[index] == 0);
}

static void test_metadata_predicate(void)
{
    assert(moc_policy_metadata_is_safe(0, S_IFREG | 0644, 1));
    assert(moc_policy_metadata_is_safe(0, S_IFREG | 0600, 65536));
    assert(!moc_policy_metadata_is_safe(501, S_IFREG | 0600, 100));
    assert(!moc_policy_metadata_is_safe(0, S_IFREG | 0660, 100));
    assert(!moc_policy_metadata_is_safe(0, S_IFDIR | 0600, 100));
    assert(!moc_policy_metadata_is_safe(0, S_IFREG | 0600, 0));
    assert(!moc_policy_metadata_is_safe(0, S_IFREG | 0600, 65537));
}

static void test_file_load_rejects_non_root_and_symlink_fixtures(void)
{
    char target[] = "/tmp/meraki-openconnect-policy.XXXXXX";
    char link_path[sizeof(target) + 8];
    struct moc_policy policy = {0};
    int fd = mkstemp(target);

    assert(fd >= 0);
    assert(write(fd, VALID_POLICY, sizeof(VALID_POLICY) - 1) ==
        (ssize_t)(sizeof(VALID_POLICY) - 1));
    assert(close(fd) == 0);
    assert(moc_policy_load(target, &policy) != 0);
    assert(snprintf(link_path, sizeof(link_path), "%s.link", target) > 0);
    assert(symlink(target, link_path) == 0);
    assert(moc_policy_load(link_path, &policy) != 0);
    assert(unlink(link_path) == 0);
    assert(unlink(target) == 0);
}

int main(void)
{
    test_parse_valid_policy();
    test_rejects_missing_duplicate_and_unknown_keys();
    test_rejects_invalid_counts_addresses_paths_and_digests();
    test_accepts_canonical_and_rejects_truncated_spki_pins();
    test_requires_final_newline();
    test_clear_zeroes_all_policy_bytes();
    test_metadata_predicate();
    test_file_load_rejects_non_root_and_symlink_fixtures();
#ifdef __APPLE__
    test_rejects_extended_acl();
#endif
    puts("native policy tests passed");
    return EXIT_SUCCESS;
}
