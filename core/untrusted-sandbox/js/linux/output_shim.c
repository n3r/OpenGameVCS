#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILES 10000U
#define MAX_PATH_BYTES 4096U
#define MAX_TOTAL_BYTES (256ULL * 1024ULL * 1024ULL)
#define MAX_DEPTH 64U

typedef struct {
  uint32_t state[8];
  uint64_t bit_count;
  unsigned char block[64];
  size_t block_length;
} sha256_context;

typedef struct {
  char **items;
  size_t length;
  size_t capacity;
} path_list;

static const uint32_t sha256_constants[64] = {
  0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
  0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
  0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
  0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
  0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
  0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
  0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
  0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t rotate_right(uint32_t value, uint32_t count) {
  return (value >> count) | (value << (32U - count));
}

static void sha256_transform(sha256_context *context, const unsigned char block[64]) {
  uint32_t words[64];
  uint32_t a, b, c, d, e, f, g, h;
  size_t index;
  for (index = 0; index < 16; index += 1) {
    size_t offset = index * 4;
    words[index] = ((uint32_t)block[offset] << 24) | ((uint32_t)block[offset + 1] << 16) | ((uint32_t)block[offset + 2] << 8) | (uint32_t)block[offset + 3];
  }
  for (index = 16; index < 64; index += 1) {
    uint32_t s0 = rotate_right(words[index - 15], 7) ^ rotate_right(words[index - 15], 18) ^ (words[index - 15] >> 3);
    uint32_t s1 = rotate_right(words[index - 2], 17) ^ rotate_right(words[index - 2], 19) ^ (words[index - 2] >> 10);
    words[index] = words[index - 16] + s0 + words[index - 7] + s1;
  }
  a = context->state[0]; b = context->state[1]; c = context->state[2]; d = context->state[3];
  e = context->state[4]; f = context->state[5]; g = context->state[6]; h = context->state[7];
  for (index = 0; index < 64; index += 1) {
    uint32_t upper_e = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
    uint32_t choose = (e & f) ^ ((~e) & g);
    uint32_t temporary1 = h + upper_e + choose + sha256_constants[index] + words[index];
    uint32_t upper_a = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
    uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temporary2 = upper_a + majority;
    h = g; g = f; f = e; e = d + temporary1; d = c; c = b; b = a; a = temporary1 + temporary2;
  }
  context->state[0] += a; context->state[1] += b; context->state[2] += c; context->state[3] += d;
  context->state[4] += e; context->state[5] += f; context->state[6] += g; context->state[7] += h;
}

static void sha256_init(sha256_context *context) {
  static const uint32_t initial[8] = { 0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U };
  memcpy(context->state, initial, sizeof(initial));
  context->bit_count = 0; context->block_length = 0;
}

static void sha256_update(sha256_context *context, const void *source, size_t length) {
  const unsigned char *bytes = (const unsigned char *)source;
  size_t offset = 0;
  context->bit_count += (uint64_t)length * 8ULL;
  while (offset < length) {
    size_t available = 64U - context->block_length;
    size_t count = length - offset < available ? length - offset : available;
    memcpy(context->block + context->block_length, bytes + offset, count);
    context->block_length += count; offset += count;
    if (context->block_length == 64U) { sha256_transform(context, context->block); context->block_length = 0; }
  }
}

static void sha256_final(sha256_context *context, unsigned char digest[32]) {
  uint64_t original_bits = context->bit_count;
  unsigned char padding[128] = { 0x80 };
  unsigned char length_bytes[8];
  size_t padding_length = context->block_length < 56U ? 56U - context->block_length : 120U - context->block_length;
  size_t index;
  for (index = 0; index < 8; index += 1) length_bytes[7U - index] = (unsigned char)(original_bits >> (index * 8U));
  sha256_update(context, padding, padding_length);
  sha256_update(context, length_bytes, sizeof(length_bytes));
  for (index = 0; index < 8; index += 1) {
    digest[index * 4] = (unsigned char)(context->state[index] >> 24);
    digest[index * 4 + 1] = (unsigned char)(context->state[index] >> 16);
    digest[index * 4 + 2] = (unsigned char)(context->state[index] >> 8);
    digest[index * 4 + 3] = (unsigned char)context->state[index];
  }
}

static int write_all(const void *source, size_t length) {
  const unsigned char *bytes = (const unsigned char *)source;
  size_t offset = 0;
  while (offset < length) {
    ssize_t written = write(STDOUT_FILENO, bytes + offset, length - offset);
    if (written < 0) { if (errno == EINTR) continue; return -1; }
    offset += (size_t)written;
  }
  return 0;
}

static int emit(sha256_context *aggregate, const void *source, size_t length) {
  if (write_all(source, length) != 0) return -1;
  sha256_update(aggregate, source, length);
  return 0;
}

static void encode_u32(uint32_t value, unsigned char output[4]) {
  output[0] = (unsigned char)(value >> 24); output[1] = (unsigned char)(value >> 16); output[2] = (unsigned char)(value >> 8); output[3] = (unsigned char)value;
}

static void encode_u64(uint64_t value, unsigned char output[8]) {
  size_t index;
  for (index = 0; index < 8; index += 1) output[7U - index] = (unsigned char)(value >> (index * 8U));
}

static int decode_hex(unsigned char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  return -1;
}

static int read_binding(unsigned char binding[32]) {
  unsigned char encoded[64];
  int descriptor = open("/input/binding", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  size_t offset = 0;
  if (descriptor < 0) return -1;
  while (offset < sizeof(encoded)) {
    ssize_t count = read(descriptor, encoded + offset, sizeof(encoded) - offset);
    if (count < 0) { if (errno == EINTR) continue; close(descriptor); return -1; }
    if (count == 0) { close(descriptor); return -1; }
    offset += (size_t)count;
  }
  {
    unsigned char extra;
    if (read(descriptor, &extra, 1) != 0) { close(descriptor); return -1; }
  }
  close(descriptor);
  for (offset = 0; offset < 32; offset += 1) {
    int high = decode_hex(encoded[offset * 2]); int low = decode_hex(encoded[offset * 2 + 1]);
    if (high < 0 || low < 0) return -1;
    binding[offset] = (unsigned char)((high << 4) | low);
  }
  return 0;
}

static int add_path(path_list *paths, const char *value) {
  char *copy;
  if (paths->length >= MAX_FILES) return -1;
  if (paths->length == paths->capacity) {
    size_t next = paths->capacity == 0 ? 64 : paths->capacity * 2;
    char **items = realloc(paths->items, next * sizeof(*items));
    if (items == NULL) return -1;
    paths->items = items; paths->capacity = next;
  }
  copy = strdup(value);
  if (copy == NULL) return -1;
  paths->items[paths->length++] = copy;
  return 0;
}

static int collect_paths(int directory_fd, const char *prefix, unsigned depth, path_list *paths) {
  int duplicate_fd;
  DIR *directory;
  struct dirent *entry;
  if (depth > MAX_DEPTH) return -1;
  duplicate_fd = dup(directory_fd);
  if (duplicate_fd < 0) return -1;
  directory = fdopendir(duplicate_fd);
  if (directory == NULL) { close(duplicate_fd); return -1; }
  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    struct stat details;
    char path[MAX_PATH_BYTES + 1];
    int count;
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
    count = prefix[0] == '\0' ? snprintf(path, sizeof(path), "%s", entry->d_name) : snprintf(path, sizeof(path), "%s/%s", prefix, entry->d_name);
    if (count < 1 || (size_t)count >= sizeof(path)) { closedir(directory); return -1; }
    if (fstatat(directory_fd, entry->d_name, &details, AT_SYMLINK_NOFOLLOW) != 0) { closedir(directory); return -1; }
    if (S_ISDIR(details.st_mode)) {
      int child = openat(directory_fd, entry->d_name, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
      int result;
      if (child < 0) { closedir(directory); return -1; }
      result = collect_paths(child, path, depth + 1U, paths);
      close(child);
      if (result != 0) { closedir(directory); return -1; }
    } else if (S_ISREG(details.st_mode)) {
      if (details.st_size < 0 || (uint64_t)details.st_size > MAX_TOTAL_BYTES || add_path(paths, path) != 0) { closedir(directory); return -1; }
    } else {
      closedir(directory); return -1;
    }
    errno = 0;
  }
  if (errno != 0) { closedir(directory); return -1; }
  return closedir(directory) == 0 ? 0 : -1;
}

static int compare_paths(const void *left, const void *right) {
  const char *const *a = (const char *const *)left;
  const char *const *b = (const char *const *)right;
  return strcmp(*a, *b);
}

static int digest_file(int descriptor, uint64_t length, unsigned char digest[32]) {
  sha256_context hash;
  unsigned char buffer[65536];
  uint64_t remaining = length;
  sha256_init(&hash);
  while (remaining > 0) {
    size_t requested = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
    ssize_t count = read(descriptor, buffer, requested);
    if (count < 0) { if (errno == EINTR) continue; return -1; }
    if (count == 0) return -1;
    sha256_update(&hash, buffer, (size_t)count);
    remaining -= (uint64_t)count;
  }
  {
    unsigned char extra;
    if (read(descriptor, &extra, 1) != 0) return -1;
  }
  sha256_final(&hash, digest);
  return lseek(descriptor, 0, SEEK_SET) == 0 ? 0 : -1;
}

static int emit_file(sha256_context *aggregate, int root_fd, const char *path, uint64_t *total) {
  int descriptor = openat(root_fd, path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat details;
  unsigned char tag = 0x01;
  unsigned char header[12];
  unsigned char file_digest[32];
  unsigned char buffer[65536];
  size_t path_length = strlen(path);
  uint64_t remaining;
  if (descriptor < 0 || fstat(descriptor, &details) != 0 || !S_ISREG(details.st_mode) || details.st_size < 0 || path_length < 1 || path_length > MAX_PATH_BYTES) { if (descriptor >= 0) close(descriptor); return -1; }
  if ((uint64_t)details.st_size > MAX_TOTAL_BYTES - *total || digest_file(descriptor, (uint64_t)details.st_size, file_digest) != 0) { close(descriptor); return -1; }
  encode_u32((uint32_t)path_length, header); encode_u64((uint64_t)details.st_size, header + 4);
  if (emit(aggregate, &tag, 1) != 0 || emit(aggregate, header, sizeof(header)) != 0 || emit(aggregate, file_digest, sizeof(file_digest)) != 0 || emit(aggregate, path, path_length) != 0) { close(descriptor); return -1; }
  remaining = (uint64_t)details.st_size;
  while (remaining > 0) {
    size_t requested = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
    ssize_t count = read(descriptor, buffer, requested);
    if (count < 0) { if (errno == EINTR) continue; close(descriptor); return -1; }
    if (count == 0 || emit(aggregate, buffer, (size_t)count) != 0) { close(descriptor); return -1; }
    remaining -= (uint64_t)count;
  }
  close(descriptor);
  *total += (uint64_t)details.st_size;
  return 0;
}

int main(void) {
  static const unsigned char magic[8] = { 0x4f, 0x47, 0x56, 0x43, 0x53, 0x42, 0x31, 0x00 };
  unsigned char binding[32];
  unsigned char terminal[13];
  unsigned char aggregate_digest[32];
  sha256_context aggregate;
  path_list paths = { 0 };
  int root_fd;
  uint64_t total = 0;
  size_t index;
  if (read_binding(binding) != 0) return 64;
  root_fd = open("/output", O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
  if (root_fd < 0 || collect_paths(root_fd, "", 0, &paths) != 0) { if (root_fd >= 0) close(root_fd); return 65; }
  qsort(paths.items, paths.length, sizeof(*paths.items), compare_paths);
  sha256_init(&aggregate);
  if (emit(&aggregate, magic, sizeof(magic)) != 0 || emit(&aggregate, binding, sizeof(binding)) != 0) { close(root_fd); return 66; }
  for (index = 0; index < paths.length; index += 1) {
    if (index > 0 && strcmp(paths.items[index - 1], paths.items[index]) >= 0) { close(root_fd); return 67; }
    if (emit_file(&aggregate, root_fd, paths.items[index], &total) != 0) { close(root_fd); return 68; }
  }
  close(root_fd);
  terminal[0] = 0xff; encode_u32((uint32_t)paths.length, terminal + 1); encode_u64(total, terminal + 5);
  if (emit(&aggregate, terminal, sizeof(terminal)) != 0) return 69;
  sha256_final(&aggregate, aggregate_digest);
  if (write_all(aggregate_digest, sizeof(aggregate_digest)) != 0) return 70;
  for (index = 0; index < paths.length; index += 1) free(paths.items[index]);
  free(paths.items);
  return 0;
}
