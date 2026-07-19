#include "protocol.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int read_exact(int fd, unsigned char *buffer, size_t length, int allow_clean_eof)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = read(fd, buffer + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count == 0)
            return offset == 0 && allow_clean_eof ? MOC_PROTOCOL_EOF : MOC_PROTOCOL_TRUNCATED;
        if (errno == EINTR)
            continue;
        return MOC_PROTOCOL_IO;
    }
    return MOC_PROTOCOL_OK;
}

static int write_exact(int fd, const unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = write(fd, buffer + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR)
            continue;
        return MOC_PROTOCOL_IO;
    }
    return MOC_PROTOCOL_OK;
}

static size_t required_fields(enum moc_message_type type)
{
    switch (type) {
    case MOC_MSG_WEBVIEW_REQUIRED:
    case MOC_MSG_STAGE:
        return 1;
    case MOC_MSG_CONNECTED:
        return 4;
    case MOC_MSG_FAILED:
    case MOC_MSG_WEBVIEW_RESULT:
        return 2;
    case MOC_MSG_DISCONNECTED:
    case MOC_MSG_CANCEL:
        return 0;
    default:
        return SIZE_MAX;
    }
}

static int field_is_printable(const char *value, size_t length)
{
    if (value == NULL)
        return length == 0;
    for (size_t index = 0; index < length; index++) {
        unsigned char byte = (unsigned char)value[index];
        if (byte < 0x20 || byte > 0x7e)
            return 0;
    }
    return 1;
}

static int validate_frame(const struct moc_frame *frame, uint32_t lengths[MOC_FIELD_COUNT])
{
    size_t expected;

    if (frame == NULL)
        return MOC_PROTOCOL_INVALID;
    expected = required_fields(frame->type);
    if (expected == SIZE_MAX)
        return MOC_PROTOCOL_INVALID;
    for (size_t index = 0; index < MOC_FIELD_COUNT; index++) {
        size_t length = frame->fields[index] == NULL ? 0 : strlen(frame->fields[index]);
        if (length > MOC_FIELD_MAX || (index < expected && length == 0) ||
            (index >= expected && length != 0) || !field_is_printable(frame->fields[index], length))
            return MOC_PROTOCOL_INVALID;
        lengths[index] = (uint32_t)length;
    }
    return MOC_PROTOCOL_OK;
}

void moc_frame_clear(struct moc_frame *frame)
{
    if (frame == NULL)
        return;
    for (size_t index = 0; index < MOC_FIELD_COUNT; index++) {
        free(frame->fields[index]);
        frame->fields[index] = NULL;
    }
    frame->type = 0;
}

int moc_write_frame(int fd, const struct moc_frame *frame)
{
    uint32_t lengths[MOC_FIELD_COUNT] = {0};
    unsigned char header[MOC_HEADER_SIZE] = {0};
    size_t offset = 0;
    int result = validate_frame(frame, lengths);

    if (result != MOC_PROTOCOL_OK)
        return result;
    header[offset++] = (unsigned char)frame->type;
    for (size_t index = 0; index < MOC_FIELD_COUNT; index++) {
        uint32_t value = lengths[index];
        header[offset++] = (unsigned char)(value >> 24);
        header[offset++] = (unsigned char)(value >> 16);
        header[offset++] = (unsigned char)(value >> 8);
        header[offset++] = (unsigned char)value;
    }
    result = write_exact(fd, header, sizeof(header));
    if (result != MOC_PROTOCOL_OK)
        return result;
    for (size_t index = 0; index < MOC_FIELD_COUNT; index++) {
        if (lengths[index] == 0)
            continue;
        result = write_exact(fd, (const unsigned char *)frame->fields[index], lengths[index]);
        if (result != MOC_PROTOCOL_OK)
            return result;
    }
    return MOC_PROTOCOL_OK;
}

int moc_read_frame(int fd, struct moc_frame *frame)
{
    unsigned char header[MOC_HEADER_SIZE] = {0};
    uint32_t lengths[MOC_FIELD_COUNT] = {0};
    size_t offset = 0;
    size_t expected;
    int result;

    if (frame == NULL)
        return MOC_PROTOCOL_INVALID;
    moc_frame_clear(frame);
    result = read_exact(fd, header, sizeof(header), 1);
    if (result != MOC_PROTOCOL_OK)
        return result;
    frame->type = (enum moc_message_type)header[offset++];
    expected = required_fields(frame->type);
    if (expected == SIZE_MAX)
        return MOC_PROTOCOL_INVALID;
    for (size_t index = 0; index < MOC_FIELD_COUNT; index++) {
        lengths[index] = ((uint32_t)header[offset] << 24) |
            ((uint32_t)header[offset + 1] << 16) |
            ((uint32_t)header[offset + 2] << 8) |
            (uint32_t)header[offset + 3];
        offset += 4;
        if (lengths[index] > MOC_FIELD_MAX || (index < expected && lengths[index] == 0) ||
            (index >= expected && lengths[index] != 0)) {
            moc_frame_clear(frame);
            return MOC_PROTOCOL_INVALID;
        }
    }
    for (size_t index = 0; index < MOC_FIELD_COUNT; index++) {
        if (lengths[index] == 0)
            continue;
        frame->fields[index] = malloc((size_t)lengths[index] + 1);
        if (frame->fields[index] == NULL) {
            moc_frame_clear(frame);
            return MOC_PROTOCOL_MEMORY;
        }
        result = read_exact(fd, (unsigned char *)frame->fields[index], lengths[index], 0);
        if (result != MOC_PROTOCOL_OK) {
            moc_frame_clear(frame);
            return result;
        }
        frame->fields[index][lengths[index]] = '\0';
        if (!field_is_printable(frame->fields[index], lengths[index])) {
            moc_frame_clear(frame);
            return MOC_PROTOCOL_INVALID;
        }
    }
    return MOC_PROTOCOL_OK;
}
