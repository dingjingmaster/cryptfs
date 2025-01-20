//
// Created by dingjing on 1/20/25.
//

#ifndef cryptfs_CRYPTFS_H
#define cryptfs_CRYPTFS_H
#include <glib.h>
#include <stdbool.h>
#include <libcryptsetup.h>

G_BEGIN_DECLS

typedef struct _CryptFs
{
    char*                           uuid;
    char*                           fsType;
    char*                           decDevice;
    char*                           deviceName;
    char*                           mountPoint;
    unsigned char                   encKey[64];
    gint                            encKeyLen;
    struct crypt_device*            device;
    struct crypt_params_plain       params;
} CryptFs;

CryptFs*    cryptfs_init            (const char* device, const char* mountPoint);
bool        cryptfs_set_passwd      (CryptFs* fs, const unsigned char* passwd, int passwdLen);
bool        cryptfs_is_format       (CryptFs* fs);
bool        cryptfs_format          (CryptFs* fs);
bool        cryptfs_mount           (CryptFs* fs);
bool        cryptfs_is_mounted      (CryptFs* fs);
bool        cryptfs_unmount         (CryptFs* fs);
void        cryptfs_destroy         (CryptFs** fs);

G_END_DECLS

#endif // cryptfs_CRYPTFS_H
