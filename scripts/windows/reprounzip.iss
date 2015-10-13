; This needs:
;   Default installation of Python 2.7 in C:\Python2.7
;   python27.dll in C:\Python2.7 (might be in Windows\system[32])
;   PyCrypto installed in Python installation
;   ssh.exe and DLLs in input\ssh
;   make sure to generate reprounzip.exe with setuptools (not distutils),
;     change shebang to #!python.exe

[Setup]
AppName=ReproUnzip
AppVerName=ReproUnzip 1.0.1
OutputBaseFilename=reprounzip-setup
DefaultGroupName=ReproZip
DefaultDirName={pf}\ReproUnzip
OutputDir=output

[Files]
; Base Python files
Source: C:\Python2.7\*; DestDir: {app}\python2.7; Flags: recursesubdirs
Source: input\reprounzip.bat; DestDir: {app}
; SSH
Source: input\ssh\*; DestDir: {app}\ssh

[UninstallDelete]
; Makes sure .pyc files don't get left behind
Type: filesandordirs; Name: {app}\python2.7\Lib
