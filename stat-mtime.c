#include <sys/stat.h>
#include <stdio.h>
int main() {
    struct stat stat_result;
    if(!lstat("/", &stat_result)) {
        printf("mtime = %lu.%lu\n", stat_result.st_mtim.tv_sec, stat_result.st_mtim.tv_nsec);
    } else {
        printf("error\n");
        return 1;
    }
}
