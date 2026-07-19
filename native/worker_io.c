#include "worker_io.h"

#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

int moc_isolate_protocol(int *input_fd, int *output_fd)
{
    int input;
    int output;
    int null_fd;

    if (input_fd == NULL || output_fd == NULL)
        return -1;
    input = fcntl(STDIN_FILENO, F_DUPFD_CLOEXEC, 3);
    if (input < 0)
        return -1;
    output = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
    if (output < 0) {
        (void)close(input);
        return -1;
    }
    null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null_fd >= 0 && null_fd <= STDERR_FILENO) {
        int replacement = fcntl(null_fd, F_DUPFD_CLOEXEC, 3);
        (void)close(null_fd);
        null_fd = replacement;
    }
    if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 ||
        dup2(null_fd, STDOUT_FILENO) < 0 || dup2(null_fd, STDERR_FILENO) < 0) {
        if (null_fd >= 0)
            (void)close(null_fd);
        (void)close(input);
        (void)close(output);
        return -1;
    }
    (void)close(null_fd);
    *input_fd = input;
    *output_fd = output;
    return 0;
}
