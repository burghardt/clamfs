SUBDIRS = svg

man_MANS = clamfs.1

EXTRA_DIST = Doxyfile.in \
             clamfs.xml \
             debug.xml \
             clamfs.1

doxygen:
	doxygen

clean:
	rm -fr html latex
