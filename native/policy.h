#ifndef MOC_VPN_POLICY_H
#define MOC_VPN_POLICY_H

#include <arpa/inet.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openconnect.h>

#define MOC_MAX_DNS_RULES 16u
#define MOC_MAX_DNS_SERVERS 3u
#define MOC_ROOT_POLICY "/Library/PrivilegedHelperTools/io.github.k0nkupa.meraki-openconnect.policy.conf"
#define MOC_USER_AGENT "AnyConnect Linux_64 4.7.00136"
#define MOC_VERSION_STRING "4.7.00136"
#define MOC_REPORTED_OS "linux-64"
#define MOC_VPNC_SCRIPT "/Library/PrivilegedHelperTools/io.github.k0nkupa.meraki-openconnect.vpnc-script"
#define MOC_RUNTIME_DIR "/var/run/meraki-openconnect"
#define MOC_PID_PATH MOC_RUNTIME_DIR "/tunnel.pid"

struct moc_dns_rule {
    char domain[254];
    char nameservers[MOC_MAX_DNS_SERVERS][INET6_ADDRSTRLEN];
    size_t nameserver_count;
};

struct moc_policy {
    char digest[72];
    char gateway[254];
    char servercert[256];
    char login_path[256];
    char final_path[256];
    char token_cookie[128];
    struct moc_dns_rule dns_rules[MOC_MAX_DNS_RULES];
    size_t dns_rule_count;
};

int moc_policy_load(const char *path, struct moc_policy *policy);
int moc_policy_parse(const char *text, size_t length, struct moc_policy *policy);
int moc_policy_metadata_is_safe(uid_t owner, mode_t mode, off_t size);
void moc_policy_clear(struct moc_policy *policy);
int moc_uri_is_allowed(const struct moc_policy *policy, const char *uri);
int moc_final_uri_is_allowed(const struct moc_policy *policy, const char *uri);
int moc_form_is_browser_only(const struct oc_auth_form *form);

#endif
