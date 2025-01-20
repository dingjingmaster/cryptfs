#include <stdio.h>
#include "cryptfs.h"

int main(void)
{
    const unsigned char* key = "123456";
    const char* devName = "/tmp/aaa.iso";
    const char* mountPoint = "/tmp/test";

    CryptFs* cfs = cryptfs_init(devName, mountPoint);
    if (!cfs) {
        printf("Failed to initialize CryptFS\n");
        goto out;
    }

    if (!cryptfs_set_passwd(cfs, key, (int) strlen((char*)key))) {
        printf("Failed to set password\n");
        goto out;
    }

    if (!cryptfs_is_format(cfs)) {
        printf("Not format\n");
        if (!cryptfs_format(cfs)) {
            printf("Format error\n");
            goto out;
        }
    }

    if (!cryptfs_mount(cfs)) {
        printf("Mount error\n");
        goto out;
    }

    if (!cryptfs_unmount(cfs)) {
        printf("Unmount error\n");
        goto out;
    }

    printf("Success\n");

out:
    cryptfs_destroy(&cfs);

    return 0;
}
