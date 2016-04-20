#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
int main(int argc, char *argv[]) {
    struct stat stat_result;
    if (argc < 2) exit (1);
    if(!lstat(argv[1], &stat_result)) {
        printf("mtime = %ld.%09ld\n", stat_result.st_mtim.tv_sec, stat_result.st_mtim.tv_nsec);
    } else {
        printf("error\n");
        return 1;
    }
}
