#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "policy.h"
#include "protocol.h"
#include "worker_io.h"

static void test_worker_uses_stock_vpnc_script(void)
{
    assert(strcmp(MOC_VPNC_SCRIPT,
        "/Library/PrivilegedHelperTools/"
        "io.github.k0nkupa.meraki-openconnect.vpnc-script") == 0);
}

static void test_worker_uses_neutral_tunnel_pid_path(void)
{
    assert(strcmp(MOC_PID_PATH, "/var/run/meraki-openconnect/tunnel.pid") == 0);
}

static void test_protocol_is_isolated_from_child_stdio(void)
{
    int input_pipe[2];
    int output_pipe[2];
    pid_t child;
    struct moc_frame received = {0};

    assert(pipe(input_pipe) == 0);
    assert(pipe(output_pipe) == 0);
    child = fork();
    assert(child >= 0);
    if (child == 0) {
        int protocol_input = -1;
        int protocol_output = -1;
        struct moc_frame stage = {
            .type = MOC_MSG_STAGE,
            .fields = {"tun", NULL, NULL, NULL},
        };

        assert(dup2(input_pipe[0], STDIN_FILENO) == STDIN_FILENO);
        assert(dup2(output_pipe[1], STDOUT_FILENO) == STDOUT_FILENO);
        assert(close(input_pipe[0]) == 0);
        assert(close(input_pipe[1]) == 0);
        assert(close(output_pipe[0]) == 0);
        assert(close(output_pipe[1]) == 0);
        assert(moc_isolate_protocol(&protocol_input, &protocol_output) == 0);
        assert((fcntl(protocol_input, F_GETFD) & FD_CLOEXEC) != 0);
        assert((fcntl(protocol_output, F_GETFD) & FD_CLOEXEC) != 0);
        assert(write(STDOUT_FILENO, "Connect Banner:\n", 16) == 16);
        assert(moc_write_frame(protocol_output, &stage) == MOC_PROTOCOL_OK);
        assert(close(protocol_input) == 0);
        assert(close(protocol_output) == 0);
        _exit(EXIT_SUCCESS);
    }

    assert(close(input_pipe[0]) == 0);
    assert(close(input_pipe[1]) == 0);
    assert(close(output_pipe[1]) == 0);
    assert(moc_read_frame(output_pipe[0], &received) == MOC_PROTOCOL_OK);
    assert(received.type == MOC_MSG_STAGE);
    assert(strcmp(received.fields[0], "tun") == 0);
    moc_frame_clear(&received);
    assert(moc_read_frame(output_pipe[0], &received) == MOC_PROTOCOL_EOF);
    assert(close(output_pipe[0]) == 0);
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status));
    assert(WEXITSTATUS(status) == EXIT_SUCCESS);
}

static void test_frame_round_trip(void)
{
    int fds[2];
    struct moc_frame sent = {
        .type = MOC_MSG_WEBVIEW_REQUIRED,
        .fields = {
            "https://vpn.example.com/saml/sp/login?state=abc",
            NULL,
            NULL,
            NULL,
        },
    };
    struct moc_frame received = {0};

    assert(pipe(fds) == 0);
    assert(moc_write_frame(fds[1], &sent) == MOC_PROTOCOL_OK);
    assert(close(fds[1]) == 0);
    assert(moc_read_frame(fds[0], &received) == MOC_PROTOCOL_OK);
    assert(received.type == sent.type);
    assert(strcmp(received.fields[0], sent.fields[0]) == 0);
    assert(received.fields[1] == NULL);
    moc_frame_clear(&received);
    assert(close(fds[0]) == 0);
}

static void write_header(int fd, uint8_t type, const uint32_t lengths[MOC_FIELD_COUNT])
{
    uint8_t header[MOC_HEADER_SIZE] = {0};
    size_t offset = 0;

    header[offset++] = type;
    for (size_t index = 0; index < MOC_FIELD_COUNT; index++) {
        uint32_t value = lengths[index];
        header[offset++] = (uint8_t)(value >> 24);
        header[offset++] = (uint8_t)(value >> 16);
        header[offset++] = (uint8_t)(value >> 8);
        header[offset++] = (uint8_t)value;
    }
    assert(write(fd, header, sizeof(header)) == (ssize_t)sizeof(header));
}

static void test_rejects_unknown_type(void)
{
    int fds[2];
    const uint32_t lengths[MOC_FIELD_COUNT] = {0};
    struct moc_frame received = {0};

    assert(pipe(fds) == 0);
    write_header(fds[1], 99, lengths);
    assert(close(fds[1]) == 0);
    assert(moc_read_frame(fds[0], &received) == MOC_PROTOCOL_INVALID);
    assert(close(fds[0]) == 0);
}

static void test_rejects_oversized_field(void)
{
    int fds[2];
    const uint32_t lengths[MOC_FIELD_COUNT] = {MOC_FIELD_MAX + 1, 0, 0, 0};
    struct moc_frame received = {0};

    assert(pipe(fds) == 0);
    write_header(fds[1], MOC_MSG_WEBVIEW_REQUIRED, lengths);
    assert(close(fds[1]) == 0);
    assert(moc_read_frame(fds[0], &received) == MOC_PROTOCOL_INVALID);
    assert(close(fds[0]) == 0);
}

static void test_rejects_truncated_field(void)
{
    int fds[2];
    const uint32_t lengths[MOC_FIELD_COUNT] = {4, 0, 0, 0};
    struct moc_frame received = {0};

    assert(pipe(fds) == 0);
    write_header(fds[1], MOC_MSG_WEBVIEW_REQUIRED, lengths);
    assert(write(fds[1], "ab", 2) == 2);
    assert(close(fds[1]) == 0);
    assert(moc_read_frame(fds[0], &received) == MOC_PROTOCOL_TRUNCATED);
    assert(close(fds[0]) == 0);
}

static void test_rejects_control_and_non_ascii_bytes(void)
{
    const unsigned char invalid_values[] = {'\n', '\0', 0x7f, 0x80};

    for (size_t index = 0; index < sizeof(invalid_values); index++) {
        int fds[2];
        const uint32_t lengths[MOC_FIELD_COUNT] = {1, 0, 0, 0};
        struct moc_frame received = {0};

        assert(pipe(fds) == 0);
        write_header(fds[1], MOC_MSG_WEBVIEW_REQUIRED, lengths);
        assert(write(fds[1], &invalid_values[index], 1) == 1);
        assert(close(fds[1]) == 0);
        assert(moc_read_frame(fds[0], &received) == MOC_PROTOCOL_INVALID);
        assert(close(fds[0]) == 0);
    }
}

static void test_rejects_forbidden_fields(void)
{
    int fds[2];
    struct moc_frame invalid = {
        .type = MOC_MSG_CANCEL,
        .fields = {"payload", NULL, NULL, NULL},
    };

    assert(pipe(fds) == 0);
    assert(moc_write_frame(fds[1], &invalid) == MOC_PROTOCOL_INVALID);
    assert(close(fds[0]) == 0);
    assert(close(fds[1]) == 0);
}

static void test_gateway_uri_policy(void)
{
    struct moc_policy policy = {0};
    strcpy(policy.gateway, "vpn.example.com");
    strcpy(policy.login_path, "/saml/sp/login");

    assert(moc_uri_is_allowed(&policy,
        "https://vpn.example.com/saml/sp/login?state=abc"));
    assert(moc_uri_is_allowed(&policy,
        "https://vpn.example.com/saml/sp/login"));
    assert(!moc_uri_is_allowed(&policy, "http://vpn.example.com/saml/sp/login"));
    assert(!moc_uri_is_allowed(&policy, "https://example.com/saml/sp/login"));
    assert(!moc_uri_is_allowed(&policy,
        "https://vpn.example.com.example.com/saml/sp/login"));
    assert(!moc_uri_is_allowed(&policy,
        "https://user@vpn.example.com/saml/sp/login"));
    assert(!moc_uri_is_allowed(&policy,
        "https://vpn.example.com:444/saml/sp/login"));
    assert(!moc_uri_is_allowed(&policy,
        "https://vpn.example.com/saml/sp/login/extra"));
    assert(!moc_uri_is_allowed(&policy,
        "https://vpn.example.com/saml/sp/login#fragment"));
}

static void test_final_uri_policy(void)
{
    struct moc_policy policy = {0};
    strcpy(policy.gateway, "vpn.example.com");
    strcpy(policy.final_path, "/saml/sp/login_final");

    assert(moc_final_uri_is_allowed(&policy,
        "https://vpn.example.com/saml/sp/login_final"));
    assert(!moc_final_uri_is_allowed(&policy,
        "https://vpn.example.com/saml/sp/login_final?token=bad"));
}

static void test_auth_form_policy(void)
{
    struct oc_form_opt sso = {.type = OC_FORM_OPT_SSO_TOKEN};
    struct oc_form_opt hidden = {.type = OC_FORM_OPT_HIDDEN, .next = &sso};
    struct oc_auth_form allowed = {.opts = &hidden};
    struct oc_form_opt password = {.type = OC_FORM_OPT_PASSWORD};
    struct oc_auth_form rejected = {.opts = &password};

    assert(moc_form_is_browser_only(&allowed));
    assert(!moc_form_is_browser_only(&rejected));
    assert(!moc_form_is_browser_only(NULL));
}

int main(void)
{
    test_worker_uses_stock_vpnc_script();
    test_worker_uses_neutral_tunnel_pid_path();
    test_protocol_is_isolated_from_child_stdio();
    test_frame_round_trip();
    test_rejects_unknown_type();
    test_rejects_oversized_field();
    test_rejects_truncated_field();
    test_rejects_control_and_non_ascii_bytes();
    test_rejects_forbidden_fields();
    test_gateway_uri_policy();
    test_final_uri_policy();
    test_auth_form_policy();
    puts("native protocol tests passed");
    return EXIT_SUCCESS;
}
