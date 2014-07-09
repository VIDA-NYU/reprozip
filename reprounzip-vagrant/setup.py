from setuptools import setup


description = """\
Plugin for ReproZip adding Vagrant support to the unpacker.

This requires reprounzip. It adds the 'reprounzip vagrant' subcommand which
builds a virtual machine template from a packed experiment, allowing to run it
on a different system/architecture (notably on Windows). You will need Vagrant
to run this virtual machine template.
"""
setup(name='reprounzip-vagrant',
      version='0.2',
      packages=['reprounzip', 'reprounzip.unpackers'],
      entry_points={
          'reprounzip.unpackers': [
              'vagrant = reprounzip.unpackers.vagrant:setup']},
      namespace_packages=['reprounzip', 'reprounzip.unpackers'],
      install_requires=[
          'reprounzip>=0.2',
          'rpaths>=0.4'],
      description='Allows the ReproZip unpacker to create virtual machines',
      author="Remi Rampin",
      author_email='remirampin@gmail.com',
      url='http://github.com/ViDA-NYU/reprozip',
      long_description=description,
      license='BSD',
      keywords=['reprozip', 'reprounzip', 'reproducibility', 'provenance',
                'vida', 'nyu'],
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Science/Research',
          'License :: OSI Approved :: BSD License',
          'Topic :: Scientific/Engineering',
          'Topic :: System :: Archiving'])
