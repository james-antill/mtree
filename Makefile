
all: stat-mtime readdir mtree.pyo

stat-mtime: stat-mtime.c
	@gcc -o stat-mtime stat-mtime.c -Wall -W -O1
	@echo Compiling stat-mtime

readdir: readdir.c
	@gcc -o readdir readdir.c -Wall -W -O1
	@echo Compiling readdir

mtree.pyc: mtree.py
	@python    -m compileall mtree.py
mtree.pyo: mtree.py
	@python -O -m compileall mtree.py

clean:
	rm -f stat-mtime readdir
	rm -f *.pyo *.pyc
