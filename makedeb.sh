#!/bin/sh

git clean -fx

echo "Version is $1"

VERSION=$1
BUILDDIR=/home/massi/Workspace/vdepn/build
PATH="/sbin:$PATH"

./autogen.sh
./configure --prefix=/usr && \
make DESTDIR=${BUILDDIR} install

echo "Modifying control file"

sed -i "s/Version: [0-9].[0-9].*/Version: ${VERSION}/" ${BUILDDIR}/DEBIAN/control

dpkg -b ${BUILDDIR} vdepn-${VERSION}_debian.deb

su -c "dpkg -i vdepn-${VERSION}_debian.deb"
