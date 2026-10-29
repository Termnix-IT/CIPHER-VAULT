#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

struct cv_info { uint64_t device, inode; uint32_t user, mode, kind; };
uint32_t cv_user(void) { return (uint32_t)geteuid(); }
int cv_path_info(const char *path, struct cv_info *out) {
    struct stat info;
    if (lstat(path, &info) != 0) return -1;
    out->device = info.st_dev; out->inode = info.st_ino; out->user = info.st_uid; out->mode = info.st_mode;
    out->kind = S_ISDIR(info.st_mode) ? 1 : S_ISSOCK(info.st_mode) ? 2 : 0;
    return 0;
}
int cv_listen(const char *path) {
    struct sockaddr_un address = {0};
    if (strlen(path) >= sizeof(address.sun_path)) return -1;
    address.sun_family = AF_UNIX; memcpy(address.sun_path, path, strlen(path) + 1);
#if defined(__APPLE__)
    address.sun_len = sizeof(address);
#endif
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 || bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        chmod(path, 0600) != 0 || listen(fd, 1) != 0) { close(fd); return -1; }
    return fd;
}
int cv_peer(int fd, int *pid, uint32_t *user) {
#if defined(__linux__)
    struct ucred credentials; socklen_t size = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0 || size != sizeof(credentials)) return -1;
    *pid = credentials.pid; *user = credentials.uid; return 0;
#elif defined(__APPLE__)
    uid_t uid; gid_t gid; pid_t process; socklen_t size = sizeof(process);
    if (getpeereid(fd, &uid, &gid) != 0 || getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &process, &size) != 0 || size != sizeof(process)) return -1;
    *pid = process; *user = uid; return 0;
#else
    return -1;
#endif
}
