.PHONY:default clean install
version_file=VERSION
version := $(shell cat ${version_file})

default:
	python3 setup.py sdist && ls -l dist/psdig-$(version).tar.gz

clean:
	rm -rf psdig.egg-info build dist psdig/__pycache__

install:
	pip3 install dist/psdig-$(version).tar.gz
