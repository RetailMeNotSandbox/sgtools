PROJECT=sgtools
PYTHON := /usr/bin/env python

default:
	@echo "install: install the package and scripts"
	@echo "clean: remove build/test artifacts"
	@echo "lint: check syntax"

install:
	python setup.py install

clean:
	find . -name \*.pyc -exec rm -f {} \;
	rm -rf build dist situ.egg-info

lint:
	@echo Checking for Python syntax...
	flake8 --ignore=E123,E501 $(PROJECT) && echo OK
