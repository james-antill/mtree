
all: stat-mtime readdir

stat-mtime: stat-mtime.c
	@gcc -o stat-mtime stat-mtime.c -Wall -W -O1
	@echo Compiling stat-mtime

readdir: readdir.c
	@gcc -o readdir readdir.c -Wall -W -O1
	@echo Compiling readdir

clean:
	rm -f stat-mtime readdir
