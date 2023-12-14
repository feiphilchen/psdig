.PHONY:default clean install test
version_file=VERSION
version := $(shell cat ${version_file})

ifeq ($(V),1)
verbose_opt=-v
else
verbose_opt=
endif

default:
	python3 setup.py sdist && ls -l dist/psdig-$(version).tar.gz

clean:
	rm -rf psdig.egg-info build dist psdig/__pycache__ .pytest_cache
	make -C test clean
install:
	pip3 install $(verbose_opt) dist/psdig-$(version).tar.gz

test:
	make -C test
