#ifndef MOC_VPN_PROTOCOL_H
#define MOC_VPN_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define MOC_FIELD_MAX 8192u
#define MOC_FIELD_COUNT 4u
#define MOC_HEADER_SIZE (1u + (MOC_FIELD_COUNT * 4u))

enum moc_protocol_result {
    MOC_PROTOCOL_OK = 0,
    MOC_PROTOCOL_EOF = 1,
    MOC_PROTOCOL_INVALID = -1,
    MOC_PROTOCOL_TRUNCATED = -2,
    MOC_PROTOCOL_IO = -3,
    MOC_PROTOCOL_MEMORY = -4,
};

enum moc_message_type {
    MOC_MSG_WEBVIEW_REQUIRED = 1,
    MOC_MSG_STAGE = 2,
    MOC_MSG_CONNECTED = 3,
    MOC_MSG_FAILED = 4,
    MOC_MSG_DISCONNECTED = 5,
    MOC_MSG_WEBVIEW_RESULT = 16,
    MOC_MSG_CANCEL = 17,
};

struct moc_frame {
    enum moc_message_type type;
    char *fields[MOC_FIELD_COUNT];
};

int moc_read_frame(int fd, struct moc_frame *frame);
int moc_write_frame(int fd, const struct moc_frame *frame);
void moc_frame_clear(struct moc_frame *frame);

#endif
