from __future__ import print_function
from setuptools import setup, find_packages
from sgtools import __version__
import sys

if sys.version_info <= (2, 7):
    error = "ERROR: sgtools requires Python 2.7 or later"
    print(error, file=sys.stderr)
    sys.exit(1)

with open('README.rst') as f:
    long_description = f.read()

setup(
    name="sgtools",
    version=__version__,
    description="Standard UNIX tools for manipulating AWS security group rules",
    long_description=long_description,
    author="Matthew Wedgwood",
    author_email="mw@rmn.com",
    url="http://github.com/RetailMeNot/sgtools",
    install_requires=[
        "acky >= 0.1",
    ],
    packages=find_packages(),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Internet",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Topic :: Internet",
    ],
    license="MIT",
    entry_points={
        "console_scripts": [
            'sgtables = sgtools.cli.sgtables:main',
            'sgmanager = sgtools.cli.sgmanager:main',
        ]},
)
