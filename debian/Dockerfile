
FROM debian:sid

# Install developer tools
RUN apt-get update \
  && apt-get install --no-install-recommends -yV \
    build-essential \
    devscripts \
    debhelper \
    equivs \
    wget \
    sudo


RUN useradd builder
RUN usermod -aG sudo builder
USER builder

COPY . /tmp/debian
WORKDIR /tmp

RUN mk-build-deps \
    --install \
    --root-cmd sudo \
    --remove \
    --tool \
    'apt-get --no-install-recommends -yV' /tmp/debian/control



# ARG VERSION


# RUN wget https://github.com/secure-systems-lab/securesystemslib/releases/download/v${VERSION}/securesystemslib-${VERSION}.tar.gz \
#           -O python-securesystemslib_${VERSION}.orig.tar.gz
# RUN wget https://github.com/secure-systems-lab/securesystemslib/releases/download/v${VERSION}/securesystemslib-${VERSION}.tar.gz.asc \
#           -O python-securesystemslib_${VERSION}.orig.tar.gz.asc

# RUN tar xf python-securesystemslib_${VERSION}.orig.tar.gz
# RUN mv debian securesystemslib-${VERSION}

# WORKDIR securesystemslib-${VERSION}


# RUN debuild --unsigned-source --unsigned-changes

# docker build -t deb-sid .
# docker run --rm -it --entrypoint bash deb-sid



# dget https://mentors.debian.net/debian/pool/main/p/python-securesystemslib/python-securesystemslib_0.28.0-1.dsc
# tar xf python-securesystemslib_0.28.0-1.debian.tar.xz
# tar xf python-securesystemslib_0.28.0.orig.tar.gz
# mv debian securesystemslib-0.28.0/
# cd securesystemslib-0.28.0
# mk-build-deps -irt 'apt-get --no-install-recommends -yV' debian/control
# DEB_BUILD_OPTIONS=nocheck debuild --unsigned-source --unsigned-changes
# apt install ./python3-securesystemslib_0.28.0-1_all.deb






# debuild --unsigned-source --unsigned-changes