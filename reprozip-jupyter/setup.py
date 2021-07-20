import io
import os
from setuptools import setup


os.chdir(os.path.abspath(os.path.dirname(__file__)))


with io.open('README.rst', encoding='utf-8') as fp:
    description = fp.read()
setup(
    name='reprozip-jupyter',
    version='2.0.0',
    packages=['reprozip_jupyter'],
    package_data={'reprozip_jupyter': ['notebook-extension.js']},
    entry_points={
        'console_scripts': [
            'reprozip-jupyter = reprozip_jupyter.main:main',
        ],
    },
    install_requires=[
        'notebook', 'jupyter_client', 'nbformat', 'nbconvert',
        'reprounzip>=2.0.0,<3.0.0',
    ],
    description="Jupyter Notebook tracing/reproduction using ReproZip",
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
    license='BSD',
    keywords=[
        'reprozip', 'reprounzip', 'reproducibility', 'provenance', 'notebook',
        'vida', 'nyu', 'jupyter',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Science/Research',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Topic :: Scientific/Engineering',
        'Topic :: System :: Archiving',
    ],
)
