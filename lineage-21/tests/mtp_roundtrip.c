/* Exercise an actual host -> MTP -> host file transfer, then remove only
 * the object created by this process. Does not enumerate personal files. */
#include <libmtp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
    if (argc != 4) { fprintf(stderr, "source download test-name\n"); return 2; }
    if (strncmp(argv[3], "codex-mtp-test-", 15)) return 2;
    struct stat st;
    if (stat(argv[1], &st)) return 2;
    LIBMTP_Init();
    LIBMTP_raw_device_t *raw = NULL;
    int count = 0;
    if (LIBMTP_Detect_Raw_Devices(&raw, &count) != LIBMTP_ERROR_NONE || count != 1)
        return 3;
    if (raw[0].device_entry.vendor_id != 0x04e8) return 3;
    LIBMTP_mtpdevice_t *dev = LIBMTP_Open_Raw_Device_Uncached(&raw[0]);
    free(raw);
    if (!dev) return 4;
    int result = 5;
    if (LIBMTP_Get_Storage(dev, LIBMTP_STORAGE_SORTBY_NOTSORTED) || !dev->storage)
        goto end;
    printf("storage_id=%u capacity=%llu\n", dev->storage->id,
           (unsigned long long)dev->storage->MaxCapacity);
    LIBMTP_file_t *file = LIBMTP_new_file_t();
    file->filename = strdup(argv[3]);
    file->filesize = st.st_size;
    file->filetype = LIBMTP_FILETYPE_UNKNOWN;
    file->storage_id = dev->storage->id;
    file->parent_id = 0;
    LIBMTP_file_t *entries = LIBMTP_Get_Files_And_Folders(dev, file->storage_id,
                                                       LIBMTP_FILES_AND_FOLDERS_ROOT);
    while (entries) {
        LIBMTP_file_t *next = entries->next;
        if (entries->filetype == LIBMTP_FILETYPE_FOLDER &&
            !strcmp(entries->filename, "Download")) file->parent_id = entries->item_id;
        LIBMTP_destroy_file_t(entries);
        entries = next;
    }
    if (!file->parent_id) { fprintf(stderr, "Download directory not found\n"); goto cleanup; }
    printf("test_parent=%u\n", file->parent_id);
    if (LIBMTP_Send_File_From_File(dev, argv[1], file, NULL, NULL)) goto cleanup;
    printf("uploaded_object=%u bytes=%lld\n", file->item_id, (long long)st.st_size);
    if (LIBMTP_Get_File_To_File(dev, file->item_id, argv[2], NULL, NULL))
        goto cleanup;
    printf("downloaded_object=%u\n", file->item_id);
    result = 0;
cleanup:
    if (file->item_id) {
        if (LIBMTP_Delete_Object(dev, file->item_id)) result = 6;
        else printf("test_object_removed=%u\n", file->item_id);
    }
    LIBMTP_destroy_file_t(file);
end:
    if (result) LIBMTP_Dump_Errorstack(dev);
    LIBMTP_Release_Device(dev);
    return result;
}
