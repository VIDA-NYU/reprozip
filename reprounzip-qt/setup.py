import io
import os
from setuptools import setup
import sys


# pip workaround
os.chdir(os.path.abspath(os.path.dirname(__file__)))


# MacOS .app with py2app
if sys.platform == 'darwin':
    extra_options = dict(
        setup_requires=['py2app'],
        app=['reprounzip_qt/main.py'],
        options=dict(py2app=dict(argv_emulation=True)))
else:
    extra_options = {}


# Need to specify encoding for PY3, which has the worst unicode handling ever
with io.open('README.rst', encoding='utf-8') as fp:
    description = fp.read()
setup(name='reprounzip-qt',
      version='0.2',
      packages=['reprounzip_qt', 'reprounzip_qt.gui'],
      entry_points={
          'gui_scripts': [
              'reprounzip-qt = reprounzip_qt.main:main']},
      install_requires=['PyYAML'],
      description="Graphical user interface for reprounzip, using Qt",
      author="Remi Rampin, Fernando Chirigati, Dennis Shasha, Juliana Freire",
      author_email='reprozip-users@vgc.poly.edu',
      maintainer="Remi Rampin",
      maintainer_email='remirampin@gmail.com',
      url='http://vida-nyu.github.io/reprozip/',
      long_description=description,
      license='BSD-3-Clause',
      keywords=['reprozip', 'reprounzip', 'reproducibility', 'provenance',
                'vida', 'nyu', 'gui'],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: X11 Applications :: Qt',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2.7',
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'],
      **extra_options)
