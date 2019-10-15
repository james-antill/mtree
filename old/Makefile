
# On mac OSX:
#     PKG_CONFIG_PATH=macos-pkg-config  make
# On Debian/Ubuntu:
#     PKG_CONFIG_PATH=debian-pkg-config make

all:                     mtree.pyo pyreaddir.so pylstat.so
xall: stat-mtime readdir mtree.pyo pyreaddir.so pylstat.so ustr-wc

PYCCARGS = $$(pkg-config --cflags --libs python) \
           -fPIC -shared

USTRCCARGS = $$(pkg-config --cflags --libs ustr)

pyreaddir.so: pyreaddir.c
	@gcc $(PYCCARGS) -o pyreaddir.so pyreaddir.c
	@echo Compiling pyreaddir

pylstat.so: pylstat.c
	@gcc $(PYCCARGS) -o pylstat.so pylstat.c
	@echo Compiling pylstat

ustr-wc: ustr-wc.c
	@gcc $(USTRCCARGS) -O2 -o ustr-wc ustr-wc.c
	@echo Compiling ustr-wc

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
	rm -f stat-mtime readdir ustr-wc
	rm -f pyreaddir.so pylstat.so
	rm -f *.pyo *.pyc
