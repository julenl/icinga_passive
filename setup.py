
from setuptools import setup, find_packages


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name = 'icinga_passive',
    version = '1.0.0.dev1',
    description = 'Tool to send monitoring metrics pasively to Icinga2',
    long_description = long_description,
    long_description_content_type="text/markdown",
    license = 'GNU General Public License v2 (GPLv2)',
    author = 'Julen Larrucea',
    author_email = 'code@larrucea.eu',
    url = 'https://github.com/julenl/icinga_passive',
    download_url = 'https://github.com/julenl/icinga_passive/archive/0.1.tar.gz',
    keywords = ['icinga', 'icinga2', 'passive', 'monitoring', 'passive'],
    classifiers = [
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Systems Administration",
        ],
    packages = find_packages(),
    #scripts = ['bin/icinga_passive_sender'],
    scripts = ['icinga_passive/icinga_passive.py', 'icinga_passive/lib_presets.py'],
    #entry_points = {
    #    'console_scripts': ['icinga_passive_sender=icinga_passive_sender:main'],
    #},
    #data_files=[
    #    ('/usr/local/bin', ['bin/icinga_passive_sender'])
    #],
    test_suite = 'tests',
)
