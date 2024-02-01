#!/bin/sh

cd "$(dirname "$0")/.."
if [ ! -d dist ]; then mkdir dist; fi
for image in manylinux2010_x86_64 manylinux2014_x86_64; do
docker run -i --rm -v "${PWD}:/src" quay.io/pypa/${image} <<'END'
yum install -y sqlite-devel
cd /src/reprozip
for PYBIN in /opt/python/*/bin; do "${PYBIN}/pip" wheel . -w ../dist; done
for WHEEL in ../dist/*.whl; do auditwheel repair "${WHEEL}" -w ../dist; done
exit 0
END
done
