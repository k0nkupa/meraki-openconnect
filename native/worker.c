#define _DARWIN_C_SOURCE

#include "policy.h"
#include "protocol.h"
#include "worker_io.h"

#include <errno.h>
#include <fcntl.h>
#include <gnutls/pkcs11.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

enum worker_stage {
    WORKER_STAGE_INIT,
    WORKER_STAGE_AUTH,
    WORKER_STAGE_CSTP,
    WORKER_STAGE_TUN,
    WORKER_STAGE_MAINLOOP,
};

struct worker_context {
    struct openconnect_info *vpninfo;
    int command_fd;
    struct moc_policy policy;
    pthread_mutex_t frame_mutex;
    pthread_cond_t frame_condition;
    struct moc_frame webview_result;
    bool webview_waiting;
    bool webview_ready;
    bool cancelled;
    bool pid_written;
    bool dtls_available;
};

static volatile sig_atomic_t signal_command_fd = -1;
static volatile sig_atomic_t signal_pid_written = 0;
static int protocol_input_fd = -1;
static int protocol_output_fd = -1;

static const char *stage_name(enum worker_stage stage)
{
    switch (stage) {
    case WORKER_STAGE_INIT:
        return "init";
    case WORKER_STAGE_AUTH:
        return "auth";
    case WORKER_STAGE_CSTP:
        return "cstp";
    case WORKER_STAGE_TUN:
        return "tun";
    case WORKER_STAGE_MAINLOOP:
        return "mainloop";
    }
    return "unknown";
}

static int emit_one(enum moc_message_type type, const char *first)
{
    struct moc_frame frame = {
        .type = type,
        .fields = {(char *)first, NULL, NULL, NULL},
    };
    return moc_write_frame(protocol_output_fd, &frame);
}

static int emit_failure(enum worker_stage stage, const char *category)
{
    struct moc_frame frame = {
        .type = MOC_MSG_FAILED,
        .fields = {(char *)stage_name(stage), (char *)category, NULL, NULL},
    };
    return moc_write_frame(protocol_output_fd, &frame);
}

static void ignore_progress(void *privdata, int level, const char *format, ...)
{
    (void)privdata;
    (void)level;
    (void)format;
}

static int validate_peer_cert(void *privdata, const char *reason)
{
    struct worker_context *context = privdata;

    (void)reason;
    if (context == NULL || context->vpninfo == NULL ||
        context->policy.servercert[0] == '\0')
        return -EINVAL;
    return openconnect_check_peer_cert_hash(
               context->vpninfo, context->policy.servercert) == 0
        ? 0
        : -EPERM;
}

static int process_auth_form(void *privdata, struct oc_auth_form *form)
{
    (void)privdata;
    return moc_form_is_browser_only(form) ? OC_FORM_RESULT_OK : OC_FORM_RESULT_ERR;
}

static int open_webview(struct openconnect_info *vpninfo, const char *uri, void *privdata)
{
    struct worker_context *context = privdata;
    struct moc_frame required = {
        .type = MOC_MSG_WEBVIEW_REQUIRED,
        .fields = {(char *)uri, NULL, NULL, NULL},
    };
    struct moc_frame result = {0};
    int protocol_result;
    int openconnect_result;

    if (context == NULL || context->vpninfo != vpninfo ||
        !moc_uri_is_allowed(&context->policy, uri))
        return -EPERM;
    if (pthread_mutex_lock(&context->frame_mutex) != 0)
        return -EIO;
    if (context->cancelled || context->webview_waiting) {
        (void)pthread_mutex_unlock(&context->frame_mutex);
        return -ECANCELED;
    }
    context->webview_waiting = true;
    context->webview_ready = false;
    if (pthread_mutex_unlock(&context->frame_mutex) != 0)
        return -EIO;

    protocol_result = moc_write_frame(protocol_output_fd, &required);
    if (protocol_result != MOC_PROTOCOL_OK) {
        if (pthread_mutex_lock(&context->frame_mutex) == 0) {
            context->webview_waiting = false;
            (void)pthread_mutex_unlock(&context->frame_mutex);
        }
        return -EPIPE;
    }
    if (pthread_mutex_lock(&context->frame_mutex) != 0)
        return -EIO;
    while (!context->webview_ready && !context->cancelled) {
        if (pthread_cond_wait(&context->frame_condition, &context->frame_mutex) != 0) {
            context->cancelled = true;
            break;
        }
    }
    if (context->webview_ready) {
        result = context->webview_result;
        memset(&context->webview_result, 0, sizeof(context->webview_result));
    }
    context->webview_waiting = false;
    context->webview_ready = false;
    bool cancelled = context->cancelled;
    if (pthread_mutex_unlock(&context->frame_mutex) != 0) {
        moc_frame_clear(&result);
        return -EIO;
    }
    if (cancelled || result.type != MOC_MSG_WEBVIEW_RESULT ||
        !moc_final_uri_is_allowed(&context->policy, result.fields[0])) {
        moc_frame_clear(&result);
        return cancelled ? -ECANCELED : -EPERM;
    }
    const char *cookies[] = {context->policy.token_cookie, result.fields[1], NULL};
    struct oc_webview_result webview = {
        .uri = result.fields[0],
        .cookies = cookies,
        .headers = NULL,
    };
    openconnect_result = openconnect_webview_load_changed(vpninfo, &webview);
    moc_frame_clear(&result);
    return openconnect_result;
}

static int initialize_openconnect(struct worker_context *context)
{
    char gateway_url[270];
    int result;

    context->command_fd = -1;
    result = snprintf(
        gateway_url, sizeof(gateway_url), "https://%s", context->policy.gateway);
    if (result <= 0 || (size_t)result >= sizeof(gateway_url))
        return -1;
    if (gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL) < 0 ||
        openconnect_init_ssl() != 0)
        return -1;
    context->vpninfo = openconnect_vpninfo_new(
        MOC_USER_AGENT, validate_peer_cert, NULL, process_auth_form, ignore_progress, context);
    if (context->vpninfo == NULL)
        return -1;
    openconnect_set_loglevel(context->vpninfo, PRG_ERR);
    openconnect_set_system_trust(context->vpninfo, 0);
    result = openconnect_set_protocol(context->vpninfo, "anyconnect");
    if (result != 0)
        return -1;
    result = openconnect_set_useragent(context->vpninfo, MOC_USER_AGENT);
    if (result != 0)
        return -1;
    result = openconnect_set_version_string(context->vpninfo, MOC_VERSION_STRING);
    if (result != 0)
        return -1;
    result = openconnect_set_reported_os(context->vpninfo, MOC_REPORTED_OS);
    if (result != 0)
        return -1;
    openconnect_set_webview_callback(context->vpninfo, open_webview);
    result = openconnect_parse_url(context->vpninfo, gateway_url);
    if (result != 0)
        return -1;
    context->command_fd = openconnect_setup_cmd_pipe(context->vpninfo);
    if (context->command_fd < 0)
        return -1;
    signal_command_fd = context->command_fd;
    return 0;
}

static int runtime_directory_is_safe(void)
{
    struct stat info;

    return lstat(MOC_RUNTIME_DIR, &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == 0 &&
        (info.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static int write_pid_file(pid_t pid)
{
    int fd;
    char buffer[32];
    int length;
    ssize_t written;

    if (!runtime_directory_is_safe())
        return -1;
    fd = open(MOC_PID_PATH, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0)
        return -1;
    length = snprintf(buffer, sizeof(buffer), "%ld\n", (long)pid);
    if (length <= 0 || (size_t)length >= sizeof(buffer)) {
        (void)close(fd);
        unlink(MOC_PID_PATH);
        return -1;
    }
    written = write(fd, buffer, (size_t)length);
    if (close(fd) != 0 || written != length) {
        unlink(MOC_PID_PATH);
        return -1;
    }
    return 0;
}

static void cancel_signal(int signal_number)
{
    const unsigned char command = OC_CMD_CANCEL;

    if (signal_command_fd >= 0) {
        (void)write((int)signal_command_fd, &command, 1);
        return;
    }
    if (signal_pid_written)
        (void)unlink(MOC_PID_PATH);
    _exit(128 + signal_number);
}

static void *cancel_watcher(void *data)
{
    struct worker_context *context = data;
    unsigned char command = OC_CMD_CANCEL;

    for (;;) {
        struct moc_frame frame = {0};
        int result = moc_read_frame(protocol_input_fd, &frame);
        bool stop = false;

        if (pthread_mutex_lock(&context->frame_mutex) != 0) {
            moc_frame_clear(&frame);
            (void)write(context->command_fd, &command, 1);
            return NULL;
        }
        if (result == MOC_PROTOCOL_OK && frame.type == MOC_MSG_WEBVIEW_RESULT &&
            context->webview_waiting && !context->webview_ready &&
            !context->cancelled) {
            context->webview_result = frame;
            memset(&frame, 0, sizeof(frame));
            context->webview_ready = true;
            (void)pthread_cond_signal(&context->frame_condition);
        } else {
            context->cancelled = true;
            stop = true;
            (void)pthread_cond_broadcast(&context->frame_condition);
        }
        (void)pthread_mutex_unlock(&context->frame_mutex);
        moc_frame_clear(&frame);
        if (!stop)
            continue;
        (void)write(context->command_fd, &command, 1);
        return NULL;
    }
}

static int install_signal_handlers(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = cancel_signal;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0)
        return -1;
    signal(SIGPIPE, SIG_IGN);
    return 0;
}

static int emit_connected(struct worker_context *context)
{
    const struct oc_ip_info *ip_info = NULL;
    char pid[32];
    const char *interface_name = openconnect_get_ifname(context->vpninfo);
    int result = openconnect_get_ip_info(context->vpninfo, &ip_info, NULL, NULL);

    if (result != 0 || ip_info == NULL || ip_info->addr == NULL || interface_name == NULL)
        return -1;
    if (snprintf(pid, sizeof(pid), "%ld", (long)getpid()) <= 0)
        return -1;
    struct moc_frame frame = {
        .type = MOC_MSG_CONNECTED,
        .fields = {
            pid,
            (char *)interface_name,
            (char *)ip_info->addr,
            context->dtls_available ? "dtls" : "cstp-fallback",
        },
    };
    return moc_write_frame(protocol_output_fd, &frame) == MOC_PROTOCOL_OK ? 0 : -1;
}

static int run_smoke(void)
{
    if (gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL) < 0)
        return EXIT_FAILURE;
    return openconnect_init_ssl() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int run_missing_policy_smoke(void)
{
    struct moc_policy policy = {0};
    int result = moc_policy_load(
        "/usr/local/etc/meraki-openconnect/does-not-exist", &policy);

    moc_policy_clear(&policy);
    return result != 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int run_early_signal_smoke(void)
{
    signal_command_fd = -1;
    signal_pid_written = 0;
    if (install_signal_handlers() != 0)
        return EXIT_FAILURE;
    (void)raise(SIGTERM);
    return EXIT_FAILURE;
}

static int run_live(void)
{
    struct worker_context context = {0};
    enum worker_stage stage = WORKER_STAGE_INIT;
    pthread_t watcher;
    bool watcher_started = false;
    bool frame_mutex_initialized = false;
    bool frame_condition_initialized = false;
    int result = EXIT_FAILURE;

    if (pthread_mutex_init(&context.frame_mutex, NULL) != 0)
        return EXIT_FAILURE;
    frame_mutex_initialized = true;
    if (pthread_cond_init(&context.frame_condition, NULL) != 0)
        goto cleanup;
    frame_condition_initialized = true;
    if (moc_isolate_protocol(&protocol_input_fd, &protocol_output_fd) != 0 ||
        geteuid() != 0 || install_signal_handlers() != 0)
        goto cleanup;
    if (moc_policy_load(MOC_ROOT_POLICY, &context.policy) != 0) {
        emit_failure(stage, "policy");
        goto cleanup;
    }
    signal_pid_written = 1;
    if (write_pid_file(getpid()) != 0) {
        signal_pid_written = 0;
        emit_failure(stage, "initialization-failed");
        goto cleanup;
    }
    context.pid_written = true;
    if (initialize_openconnect(&context) != 0) {
        emit_failure(stage, "initialization-failed");
        goto cleanup;
    }
    if (pthread_create(&watcher, NULL, cancel_watcher, &context) != 0) {
        emit_failure(stage, "cancel-watcher-failed");
        goto cleanup;
    }
    watcher_started = true;
    stage = WORKER_STAGE_AUTH;
    if (emit_one(MOC_MSG_STAGE, stage_name(stage)) != MOC_PROTOCOL_OK ||
        openconnect_obtain_cookie(context.vpninfo) != 0) {
        emit_failure(stage, "authentication-failed");
        goto cleanup;
    }
    stage = WORKER_STAGE_CSTP;
    if (emit_one(MOC_MSG_STAGE, stage_name(stage)) != MOC_PROTOCOL_OK ||
        openconnect_make_cstp_connection(context.vpninfo) != 0) {
        emit_failure(stage, "connection-rejected");
        goto cleanup;
    }
    context.dtls_available = openconnect_setup_dtls(context.vpninfo, 60) == 0;
    stage = WORKER_STAGE_TUN;
    if (emit_one(MOC_MSG_STAGE, stage_name(stage)) != MOC_PROTOCOL_OK ||
        openconnect_setup_tun_device(context.vpninfo, MOC_VPNC_SCRIPT, NULL) != 0) {
        emit_failure(stage, "tunnel-setup-failed");
        goto cleanup;
    }
    if (emit_connected(&context) != 0) {
        emit_failure(stage, "connection-report-failed");
        goto cleanup;
    }
    stage = WORKER_STAGE_MAINLOOP;
    (void)openconnect_mainloop(context.vpninfo, 300, 10);
    result = EXIT_SUCCESS;

cleanup:
    signal_command_fd = -1;
    if (watcher_started) {
        (void)pthread_cancel(watcher);
        (void)pthread_join(watcher, NULL);
    }
    if (context.vpninfo != NULL)
        openconnect_vpninfo_free(context.vpninfo);
    moc_frame_clear(&context.webview_result);
    moc_policy_clear(&context.policy);
    if (context.pid_written) {
        (void)unlink(MOC_PID_PATH);
        signal_pid_written = 0;
    }
    if (frame_condition_initialized)
        (void)pthread_cond_destroy(&context.frame_condition);
    if (frame_mutex_initialized)
        (void)pthread_mutex_destroy(&context.frame_mutex);
    (void)emit_one(MOC_MSG_DISCONNECTED, NULL);
    (void)close(protocol_input_fd);
    (void)close(protocol_output_fd);
    return result;
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "--smoke") == 0)
        return run_smoke();
    if (argc == 2 && strcmp(argv[1], "--smoke-missing-policy") == 0)
        return run_missing_policy_smoke();
    if (argc == 2 && strcmp(argv[1], "--smoke-early-signal") == 0)
        return run_early_signal_smoke();
    if (argc != 1)
        return EXIT_FAILURE;
    return run_live();
}
