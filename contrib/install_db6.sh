#!/bin/sh

# Install libdb6.2 (Berkeley DB).

export LC_ALL=C
set -e

if [ -z "${1}" ]; then
  echo "Usage: $0 <base-dir> [<extra-bdb-configure-flag> ...]"
  echo
  echo "Must specify a single argument: the directory in which db6 will be built."
  echo "This is probably \`pwd\` if you're at the root of the bitcoin repository."
  exit 1
fi

expand_path() {
  echo "$(cd "${1}" && pwd -P)"
}

BDB_PREFIX="$(expand_path ${1})/db6"; shift;
BDB_VERSION='db-6.2.23'
BDB_HASH='47612c8991aa9ac2f6be721267c8d3cdccf5ac83105df8e50809daea24e95dc7'
BDB_URL="https://download.oracle.com/berkeley-db/${BDB_VERSION}.tar.gz"

check_exists() {
  which "$1" >/dev/null 2>&1
}

sha256_check() {
  # Args: <sha256_hash> <filename>
  #
  if check_exists sha256sum; then
    echo "${1}  ${2}" | sha256sum -c
  elif check_exists sha256; then
    if [ "$(uname)" = "FreeBSD" ]; then
      sha256 -c "${1}" "${2}"
    else
      echo "${1}  ${2}" | sha256 -c
    fi
  else
    echo "${1}  ${2}" | shasum -a 256 -c
  fi
}

http_get() {
  # Args: <url> <filename> <sha256_hash>
  #
  # It's acceptable that we don't require SSL here because we manually verify
  # content hashes below.
  #
  if [ -f "${2}" ]; then
    echo "File ${2} already exists; not downloading again"
  elif check_exists curl; then
    curl --insecure --retry 5 "${1}" -o "${2}"
  else
    wget --no-check-certificate "${1}" -O "${2}"
  fi

  sha256_check "${3}" "${2}"
}

mkdir -p "${BDB_PREFIX}"
http_get "${BDB_URL}" "${BDB_VERSION}.tar.gz" "${BDB_HASH}"
tar -xzvf ${BDB_VERSION}.tar.gz -C "$BDB_PREFIX"
cd "${BDB_PREFIX}/${BDB_VERSION}/"

sed -i.old 's/WinIoCtl.h/winioctl.h/g' src/dbinc/win_db.h
sed -i.old 's/atomic_init/atomic_init_db/' src/dbinc/atomic.h src/mp/mp_region.c src/mp/mp_mvcc.c src/mp/mp_fget.c src/mutex/mut_method.c src/mutex/mut_tas.c

cd build_unix/

"${BDB_PREFIX}/${BDB_VERSION}/dist/configure" \
  --enable-cxx --disable-shared --disable-replication --with-pic --prefix="${BDB_PREFIX}" \
  "${@}"

make install

echo
echo "db6 build complete."
echo
echo 'When compiling bitcoind, run `./configure` in the following way:'
echo
echo "  export BDB_PREFIX='${BDB_PREFIX}'"
echo '  ./configure BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-6.2" BDB_CFLAGS="-I${BDB_PREFIX}/include" ...'
