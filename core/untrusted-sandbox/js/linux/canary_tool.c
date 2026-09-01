#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

static int write_all(int descriptor, const void *source, size_t length) {
  const unsigned char *bytes = source;
  size_t offset = 0;
  while (offset < length) {
    ssize_t count = write(descriptor, bytes + offset, length - offset);
    if (count < 0) { if (errno == EINTR) continue; return -1; }
    offset += (size_t)count;
  }
  return 0;
}

static int make_directory(const char *path) {
  if (mkdir(path, 0700) == 0 || errno == EEXIST) return 0;
  return -1;
}

static int valid_output(const char *path, const char *value) {
  char directory[512];
  char target[768];
  const char *slash = strchr(path, '/');
  int descriptor;
  if (slash == NULL || (size_t)(slash - path) >= sizeof(directory)) return -1;
  memcpy(directory, path, (size_t)(slash - path)); directory[slash - path] = '\0';
  if (make_directory("/output") != 0) return -1;
  snprintf(target, sizeof(target), "/output/%s", directory);
  if (make_directory(target) != 0) return -1;
  snprintf(target, sizeof(target), "/output/%s", path);
  descriptor = open(target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (descriptor < 0) return -1;
  if (write_all(descriptor, value, strlen(value)) != 0 || fsync(descriptor) != 0 || close(descriptor) != 0) return -1;
  return 0;
}

static int read_command(char output[65]) {
  int descriptor = open("/input/payload", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  ssize_t count;
  if (descriptor < 0) return -1;
  count = read(descriptor, output, 64);
  if (count < 1 || count > 64) { close(descriptor); return -1; }
  output[count] = '\0';
  {
    char extra;
    if (read(descriptor, &extra, 1) != 0) { close(descriptor); return -1; }
  }
  close(descriptor);
  return 0;
}

static int tcp_connect(const char *address, uint16_t port) {
  int descriptor = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sockaddr_in target;
  int result;
  if (descriptor < 0) return 0;
  memset(&target, 0, sizeof(target)); target.sin_family = AF_INET; target.sin_port = htons(port);
  if (inet_pton(AF_INET, address, &target.sin_addr) != 1) { close(descriptor); return -1; }
  result = connect(descriptor, (struct sockaddr *)&target, sizeof(target));
  close(descriptor);
  return result == 0 ? -1 : 0;
}

static int network_canary(void) {
  struct addrinfo *addresses = NULL;
  int dns = getaddrinfo("example.com", "443", NULL, &addresses);
  if (addresses != NULL) freeaddrinfo(addresses);
  if (tcp_connect("127.0.0.1", 1) != 0 || tcp_connect("169.254.169.254", 80) != 0 || tcp_connect("1.1.1.1", 443) != 0 || dns == 0) return 90;
  return valid_output("evidence/network", "denied") == 0 ? 0 : 91;
}

static int contains_canary(const char *path) {
  int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  char buffer[8192];
  ssize_t count;
  if (descriptor < 0) return 0;
  count = read(descriptor, buffer, sizeof(buffer)); close(descriptor);
  return count > 0 && memmem(buffer, (size_t)count, "broker-secret-canary", strlen("broker-secret-canary")) != NULL;
}

static int credential_canary(int argc, char **argv) {
  int index;
  for (index = 0; index < argc; index += 1) if (strstr(argv[index], "broker-secret-canary") != NULL) return 92;
  for (index = 0; environ[index] != NULL; index += 1) if (strstr(environ[index], "broker-secret-canary") != NULL) return 93;
  if (contains_canary("/proc/self/environ") || contains_canary("/proc/1/environ")) return 94;
  return valid_output("evidence/credential", "absent") == 0 ? 0 : 95;
}

static int absent_path_canary(void) {
  static const char *paths[] = { "/host-canary", "/root/.ssh/id_rsa", "/home/runner", "/var/run/docker.sock", "/input/undeclared", "/sibling", "/control-plane" };
  size_t index;
  for (index = 0; index < sizeof(paths) / sizeof(paths[0]); index += 1) {
    int descriptor = open(paths[index], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor >= 0) { close(descriptor); return 96; }
  }
  return valid_output("evidence/host", "absent") == 0 ? 0 : 97;
}

static int traversal_canary(void) {
  int descriptor = open("/output/../escape", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor >= 0) { close(descriptor); return 98; }
  return valid_output("evidence/traversal", "denied") == 0 ? 0 : 99;
}

static int device_canary(void) {
  if (mknod("/output/device", S_IFCHR | 0600, 0) == 0) return 100;
  return valid_output("evidence/device", "denied") == 0 ? 0 : 101;
}

static int namespace_canary(void) {
#ifdef __linux__
  if (unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET) == 0) return 111;
  return valid_output("evidence/namespace", "denied") == 0 ? 0 : 112;
#else
  return 113;
#endif
}

static int symlink_canary(void) {
  if (symlink("/etc/passwd", "/output/symlink") != 0) return 102;
  return 0;
}

static int recursion_canary(void) {
  char path[4096] = "/output";
  unsigned index;
  for (index = 0; index < 80; index += 1) {
    size_t length = strlen(path);
    if (length + 3 >= sizeof(path)) return 103;
    strcat(path, "/d");
    if (mkdir(path, 0700) != 0) return 104;
  }
  return valid_output("deep/result", "too-deep") == 0 ? 0 : 105;
}

static int disk_canary(void) {
  int descriptor = open("/output/flood", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  unsigned char buffer[1024 * 1024];
  if (descriptor < 0) return 106;
  memset(buffer, 0x5a, sizeof(buffer));
  while (write_all(descriptor, buffer, sizeof(buffer)) == 0) {}
  close(descriptor);
  return 0;
}

static int fork_canary(void) {
  pid_t children[64];
  size_t count = 0;
  while (count < sizeof(children) / sizeof(children[0])) {
    pid_t child = fork();
    if (child < 0) break;
    if (child == 0) { for (;;) pause(); }
    children[count++] = child;
  }
  if (count >= 8) return 107;
  for (;;) pause();
}

static int memory_canary(void) {
  size_t bytes = 768ULL * 1024ULL * 1024ULL;
  volatile unsigned char *memory = malloc(bytes);
  size_t index;
  if (memory == NULL) return 108;
  for (index = 0; index < bytes; index += 4096) memory[index] = (unsigned char)index;
  for (;;) pause();
}

static int stdout_canary(void) {
  unsigned char buffer[1024 * 1024];
  memset(buffer, 'x', sizeof(buffer));
  for (;;) if (write_all(STDOUT_FILENO, buffer, sizeof(buffer)) != 0) return 0;
}

int main(int argc, char **argv) {
  char command[65];
  if (read_command(command) != 0) return 63;
  if (strcmp(command, "importer") == 0) return valid_output("import/result", "dummy-import") == 0 ? 0 : 64;
  if (strcmp(command, "converter") == 0) return valid_output("preview/result", "dummy-convert") == 0 ? 0 : 65;
  if (strcmp(command, "network") == 0) return network_canary();
  if (strcmp(command, "credential") == 0) return credential_canary(argc, argv);
  if (strcmp(command, "host") == 0 || strcmp(command, "sibling") == 0 || strcmp(command, "undeclared") == 0) return absent_path_canary();
  if (strcmp(command, "traversal") == 0) return traversal_canary();
  if (strcmp(command, "device") == 0) return device_canary();
  if (strcmp(command, "namespace") == 0) return namespace_canary();
  if (strcmp(command, "symlink") == 0) return symlink_canary();
  if (strcmp(command, "recursion") == 0) return recursion_canary();
  if (strcmp(command, "disk") == 0 || strcmp(command, "bomb") == 0) return disk_canary();
  if (strcmp(command, "fork") == 0) return fork_canary();
  if (strcmp(command, "memory") == 0) return memory_canary();
  if (strcmp(command, "stdout") == 0) return stdout_canary();
  if (strcmp(command, "hang") == 0) for (;;) pause();
  if (strcmp(command, "crash") == 0) { raise(SIGSEGV); return 109; }
  return 110;
}
