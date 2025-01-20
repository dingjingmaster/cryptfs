//
// Created by dingjing on 1/20/25.
//

#include "cryptfs.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/mount.h>
#include <uuid/uuid.h>

#include "sm3.h"


static char* read_line (FILE* fr);
static void save_config (CryptFs* fs);
static void parse_config (CryptFs* fs);
static void format_path (char* filePath);


CryptFs* cryptfs_init(const char* device, const char* mountPoint)
{
    g_return_val_if_fail(device, NULL);

    CryptFs* fs = g_malloc0(sizeof(CryptFs));
    if (!fs) {
        printf("Failed to allocate crypt FS structure\n");
        return NULL;
    }

    fs->deviceName = g_strdup(device);
    if (!fs->deviceName) {
        printf("Failed to allocate device name\n");
        cryptfs_destroy(&fs);
        return NULL;
    }
    format_path(fs->deviceName);

    fs->mountPoint = g_strdup(mountPoint);
    if (!fs->mountPoint) {
        printf("Failed to allocate mount point string\n");
        cryptfs_destroy(&fs);
        return NULL;
    }
    format_path(fs->deviceName);

    // todo:// 检测系统商支持的文件系统
    fs->fsType = g_strdup("ext3");
    if (!fs->fsType) {
        printf("Failed to allocate mount point string\n");
        cryptfs_destroy(&fs);
        return NULL;
    }

    fs->encKeyLen = 32;

    int ret = crypt_init(&(fs->device), fs->deviceName);
    if (ret < 0) {
        printf("crypt init failed with error %d\n", ret);
        cryptfs_destroy(&fs);
        return NULL;
    }

    {
        fs->params.hash = "sha256";
        fs->params.offset = 0;
        fs->params.skip = 0;
        fs->params.size = 0;
    }

    // todo:// 解析配置文件
    parse_config(fs);

    // uuid
    if (!fs->uuid) {
        char uuid[128] = {0};
        uuid_t uuidT;
        uuid_generate(uuidT);
        uuid_unparse(uuidT, uuid);
        uuid[sizeof(uuid) - 1] = 0;
        fs->uuid = g_strdup(uuid);
        if (!fs->uuid) {
            printf("Failed to allocate crypt FS UUID\n");
            cryptfs_destroy(&fs);
            return NULL;
        }
    }

    fs->decDevice = g_strdup_printf("/dev/mapper/%s", fs->uuid);
    if (!(fs->decDevice)) {
        printf("Failed to get device string\n");
        cryptfs_destroy(&fs);
        return NULL;
    }

    printf("Mounted device %s\n", fs->decDevice);

    // create mount point dir

    // crypt format
    ret = crypt_format(fs->device, CRYPT_PLAIN, "aes", "xts-plain64", NULL, NULL, 512 / 8, &(fs->params));
    if (ret < 0) {
        printf("crypt format failed with error %d\n", ret);
        cryptfs_destroy(&fs);
        return NULL;
    }

    save_config(fs);

    return fs;
}

bool cryptfs_set_passwd(CryptFs * fs, const unsigned char* passwd, int passwdLen)
{
    g_return_val_if_fail(fs, false);

    const int keySize = sizeof(fs->encKey) / 2;
    sm3_hash (passwd, passwdLen, fs->encKey);
    sm3_hash (fs->encKey, keySize, fs->encKey + keySize);

    const int ret = crypt_activate_by_volume_key(fs->device, fs->uuid, fs->encKey, sizeof(fs->encKey), 0);
    if (ret < 0 && ret != -17) {
        printf("Adding key slot failed, error: %d\n", ret);
        cryptfs_destroy(&fs);
        return false;
    }

    return true;
}

bool cryptfs_is_format(CryptFs* fs)
{
    g_return_val_if_fail(fs, false);

#define SUPER_BLOCK_OFFSET      1024
#define EXT_MAGIC               0xEF53

    int fd = open (fs->decDevice, O_RDONLY);
    if (fs < 0) {
        printf("Failed to open %s\n", fs->decDevice);
        return false;
    }

    if (lseek(fd, SUPER_BLOCK_OFFSET + 56, SEEK_SET) < 0) {
        printf("Failed to seek %s\n", fs->decDevice);
        close(fd);
        return false;
    }

    uint16_t magic = 0;
    if (read(fd, &magic, sizeof(magic)) != sizeof(magic)) {
        printf("Failed to read %s\n", fs->decDevice);
        close(fd);
        return false;
    }

    close(fd);

    if (magic == EXT_MAGIC) {
        return true;
    }

    return false;
}

bool cryptfs_format(CryptFs * fs)
{
    g_return_val_if_fail(fs, false);

    char* cmd = g_strdup_printf("yes | mkfs -t %s %s", fs->fsType, fs->decDevice);
    if (cmd) {
        system(cmd);
        g_free(cmd);
    }

    return cryptfs_is_format(fs);
}

bool cryptfs_mount(CryptFs* fs)
{
    g_return_val_if_fail(fs, false);

    char* cmd = g_strdup_printf("mount -t %s /dev/mapper/%s %s", fs->fsType, fs->uuid, fs->mountPoint);
    if (cmd) {
        system(cmd);
        g_free(cmd);
    }

    return cryptfs_is_mounted(fs);
}

bool cryptfs_is_mounted(CryptFs* fs)
{
    g_return_val_if_fail(fs, false);

#define MOUNT_INFO      "/proc/self/mounts"

    bool isMounted = false;
    char* bufLine = NULL;
    FILE* f = fopen(MOUNT_INFO, "r");
    g_return_val_if_fail(f, false);

    while (NULL != (bufLine = read_line(f))) {
        isMounted = ((NULL != strstr(bufLine, fs->mountPoint)) || (NULL != strstr(bufLine, fs->decDevice)));
        if (isMounted) { break; }
        if (bufLine) {
            free(bufLine);
            bufLine = NULL;
        }
    }
    fclose(f);

    if (bufLine) {
        free(bufLine);
        bufLine = NULL;
    }

    return isMounted;
}

bool cryptfs_unmount(CryptFs* fs)
{
    g_return_val_if_fail(fs, false);

    int times = 1000;

    do {
        umount(fs->mountPoint);
        umount(fs->decDevice);
        crypt_deactivate(fs->device, fs->uuid);
    }
    while (times-- && cryptfs_is_mounted(fs));

    return !cryptfs_is_mounted(fs);
}

void cryptfs_destroy(CryptFs** fs)
{
    g_return_if_fail(fs && *fs);

    if ((*fs)->device) {
        crypt_deactivate((*fs)->device, (*fs)->uuid);
        crypt_free((*fs)->device);
        (*fs)->device = NULL;
    }

    if ((*fs)->uuid) {
        g_free((*fs)->uuid);
        (*fs)->uuid = NULL;
    }

    if ((*fs)->deviceName) {
        g_free((*fs)->deviceName);
        (*fs)->deviceName = NULL;
    }

    if ((*fs)->fsType) {
        g_free((*fs)->fsType);
        (*fs)->fsType = NULL;
    }

    if ((*fs)->decDevice) {
        g_free((*fs)->decDevice);
        (*fs)->decDevice = NULL;
    }

    if ((*fs)->mountPoint) {
        g_free((*fs)->mountPoint);
        (*fs)->mountPoint = NULL;
    }

    g_free(*fs);
    *fs = NULL;
}

static inline char* calloc_and_memcpy(const char* oldStr, int64_t oldLen, const char* addStr, int64_t addLen)
{
    int64_t newLineLen = oldLen + addLen;
    char* tmp = (char*) malloc (newLineLen + 1);
    if (!tmp) {
        return NULL;
    }

    memset(tmp, 0, newLineLen + 1);
    if (oldStr) {
        memcpy(tmp, oldStr, oldLen);
    }
    memcpy(tmp + oldLen, addStr, addLen);

    return tmp;
}

static char* read_line (FILE* fr)
{
    if (!fr) {
        printf("fopen error\n");
        return NULL;
    }
    const int64_t cur = ftell(fr);

    char* res = NULL;
    int64_t lineLen = 0;

    char buf[10] = {0};
    while (true) {
        memset(buf, 0, sizeof(buf));
        const int size = fread(buf, 1, sizeof(buf) - 1, fr);
        if (size <= 0) {
            break;
        }

        // 截取一行
        int i = 0;
        bool find = false;
        for (i = 0; i < size; ++i) {
            if (buf[i] == '\n') {
                // 找到
                char* tmp = calloc_and_memcpy(res, lineLen, buf, i);
                if (res) { free (res); res = NULL; }
                if (!tmp) { find = true; printf("impossible\n"); break; }           // impossible
                res = tmp;
                lineLen += i;
                find = true;
                break;
            }
        }

        if (find) { fseek(fr, cur + lineLen + 1, SEEK_SET); break; }

        // 分配内存, 一行的长度大于 buf
        char* tmp = calloc_and_memcpy(res, lineLen, buf, size);
        if (res) { free(res); res = NULL; }
        if (!tmp) { find = true; printf("impossible\n"); break; } // impossible
        res = tmp;
        lineLen += size;
    }

    return res;
}

static void format_path (char* filePath)
{
    if (!filePath) { return; }

    int i = 0;
    const int fLen = (int) strlen (filePath);
    for (i = 0; filePath[i]; ++i) {
        while (filePath[i] && '/' == filePath[i] && '/' == filePath[i + 1]) {
            for (int j = i; filePath[j] || j < fLen; filePath[j] = filePath[j + 1], ++j);
        }
    }

    if ((i - 1 >= 0) && filePath[i - 1] == '/') {
        filePath[i - 1] = '\0';
    }
}

static void save_config (CryptFs* fs)
{
    g_return_if_fail(fs);

#define SAVE_CONFIG(field, val) \
{ \
    char* lineBuf = g_strdup_printf("%s=%s\n", field, val); \
    if (lineBuf) { \
        fwrite(lineBuf, 1, strlen(lineBuf), fw); \
        g_free (lineBuf); \
    } \
}

    char* configFile = g_strdup_printf("%s.config", fs->deviceName);
    if (configFile) {
        FILE* fw = fopen(configFile, "w+");
        if (fw) {
            SAVE_CONFIG("uuid", fs->uuid);
            fflush(fw);
            fclose(fw);
        }
        g_free(configFile);
        configFile = NULL;
    }
}

static void parse_config (CryptFs* fs)
{
    g_return_if_fail(fs);

    char* configFile = g_strdup_printf("%s.config", fs->deviceName);
    if (configFile) {
        FILE* fr = fopen(configFile, "r");
        if (fr) {
            char* lineBuf = NULL;
            while (NULL != (lineBuf = read_line(fr))) {
                if (g_str_has_prefix(lineBuf, "uuid=")) {
                    if (fs->uuid) { free(fs->uuid); fs->uuid = NULL; }
                    fs->uuid = g_strdup(lineBuf + strlen("uuid="));
                }
                if (lineBuf) { g_free(lineBuf); lineBuf = NULL; }
            }
            fclose(fr);
            if (lineBuf) { g_free(lineBuf); lineBuf = NULL; }
        }
        g_free(configFile);
        configFile = NULL;
    }
}