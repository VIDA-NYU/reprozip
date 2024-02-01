import io
import os
from setuptools import setup


os.chdir(os.path.abspath(os.path.dirname(__file__)))


with io.open('README.rst', encoding='utf-8') as fp:
    description = fp.read()
req = [
    'packaging',
    'PyYAML',
    'usagestats>=1.0.1',
    'requests',
]
setup(
    name='reprozip-core',
    version='2.0.0',
    packages=['reprozip_core'],
    package_data={
        'reprozip_core': ['reprozip-ca.crt'],
    },
    install_requires=req,
    description="Linux tool enabling reproducible experiments (core lib)",
    author="Remi Rampin, Fernando Chirigati, Dennis Shasha, Juliana Freire",
    author_email='dev@reprozip.org',
    maintainer="Remi Rampin",
    maintainer_email='remi@rampin.org',
    url='https://www.reprozip.org/',
    project_urls={
        'Homepage': 'https://github.com/ViDA-NYU/reprozip',
        'Documentation': 'https://docs.reprozip.org/',
        'Examples': 'https://examples.reprozip.org/',
        'Say Thanks': 'https://saythanks.io/to/remram44',
        'Source': 'https://github.com/ViDA-NYU/reprozip',
        'Tracker': 'https://github.com/ViDA-NYU/reprozip/issues',
    },
    long_description=description,
    license='BSD-3-Clause',
    keywords=[
        'reprozip', 'reprounzip', 'reproducibility', 'provenance',
        'vida', 'nyu',
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Archiving',
    ],
)
