
# Use PKG_CONFIG_PATH=macos-pkg-config make on mac OSX

all:                     mtree.pyo pyreaddir.so pylstat.so
xall: stat-mtime readdir mtree.pyo pyreaddir.so pylstat.so

pyreaddir.so: pyreaddir.c
	@gcc $$(pkg-config --cflags --libs python) -fPIC -shared -o pyreaddir.so pyreaddir.c
	@echo Compiling pyreaddir

pylstat.so: pylstat.c
	@gcc $$(pkg-config --cflags --libs python) -fPIC -shared -o pylstat.so pylstat.c
	@echo Compiling pylstat

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
	rm -f pyreaddir.so pylstat.so
	rm -f *.pyo *.pyc
