
all: stat-mtime

stat-mtime: stat-mtime.c
	@gcc -o stat-mtime stat-mtime.c -Wall -W -O1
	@echo Compiling stat-mtime

clean:
	rm -f stat-mtime
