.PHONY:default clean install test deps
version_file=VERSION
install_prefix=/usr/local/share/psdig
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
	python3 -m venv $(install_prefix)/python
	$(install_prefix)/python/bin/python3 -m pip install wheel
	$(install_prefix)/python/bin/python3 -m pip install $(verbose_opt) dist/psdig-$(version).tar.gz
	$(install_prefix)/python/bin/python3 -m psdig.initialize

deps:
	bash ./scripts/install.sh --deps
test:
	make -C test
