# /path/to/virtualenv/lib/python3.8/site-packages/requests/__init__.py
# /path/to/virtualenv
#   pyvenv.cfg: has some info about environment in `key = value` format
#   share: not very much used (jupyter does), has things like manpages
#   bin: scripts from venv & entrypoints
#     activate (bash)
#     activate.ps1
#   lib
#     python3.8
#       (might be standard library files here? sometimes not)
#       site-packages
#         xxx: library
#         xxx-1.2.3.dist-info: metadata for library, might not match importname
#           RECORD: contains list of files
#           METADATA: contains name & version as well as other metadata
#         xxx.egg-link: location of library installed in 'develop' mode
#         yyy.pth: additional paths to add to sys.path, or Python code

# C:\path\to\virtualenv
#   pyvenv.cfg
#   Scripts
#     activate (bash)
#     activate.bat
#     Activate.ps1
#   Lib
#     site-packages
#       ...
#   Include
