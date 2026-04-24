#!/usr/bin/env bash

#############################
######### Variables #########
#############################

# Edit this variable to change the build options for secp256k1
SECP256K1_BUILD_OPTS="--enable-module-recovery"

#############################
####### End Variables #######
#############################

# Initialize external vars - need this to get around unbound variable errors
SKIP_GRADLE="$SKIP_GRADLE"

# Exit script if you try to use an uninitialized variable.
set -o nounset

# Exit script if a statement returns a non-true return value.
set -o errexit

# Use the error status of the first failure, rather than that of the last item in a pipeline.
set -o pipefail

# Resolve the directory that contains this script. We have to jump through a few
# hoops for this because the usual one-liners for this don't work if the script
# is a symlink
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
SCRIPTDIR="$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )"

# Determine core count for parallel make
if [[ "$OSTYPE" == "linux-gnu" ]];  then
  CORE_COUNT=$(nproc)
  OSARCH=${OSTYPE%%[0-9.]*}-`arch`
fi

if [[ "$OSTYPE" == "darwin"* ]];  then
  CORE_COUNT=$(sysctl -n hw.ncpu)
  if [[ "`machine`" == "arm"* ]]; then
    arch_name="aarch64"
    export CFLAGS="-arch arm64"
  else
    arch_name="x86-64"
    export CFLAGS="-arch x86_64"
  fi
  OSARCH="darwin-$arch_name"
fi

# add to path cargo
[ -f $HOME/.cargo/env ] && . $HOME/.cargo/env

# add to path brew
#[ -f $HOME/.zprofile ] && . $HOME/.zprofile

build_blake2bf() {

  cat <<EOF
  #############################
  ###### build blake2bf ######
  #############################
EOF

  # This version of arm blake is actually slower than java blake on arm, probably also on riscv64
  if [[ "$OSARCH" == "linux-gnu-aarch64" || "$OSARCH" == "linux-gnu-riscv64" ]];  then
    return
    #cd "$SCRIPTDIR/blake2bf/arm64"
  else if [[ "$OSARCH" == "darwin-aarch64" ]];  then
    return
    #cd "$SCRIPTDIR/blake2bf/aarch64"
  else
    cd "$SCRIPTDIR/blake2bf/x86_64"
  fi

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/blake2bf/build" || true

  if [[ -e makefile ]]; then
    make clean
  fi

  make
  mkdir -p "$SCRIPTDIR/blake2bf/build/${OSARCH}/lib"
  mv libblake2bf.* "$SCRIPTDIR/blake2bf/build/${OSARCH}/lib"
  fi
}

build_secp256k1() {

  cat <<EOF
  #############################
  ###### build secp256k1 ######
  #############################
EOF

  cd "$SCRIPTDIR/secp256k1/bitcoin-core-secp256k1"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/secp256k1/build" || true

  if [[ -e Makefile ]]; then
    make clean
  fi

  ./autogen.sh && \
    ./configure --prefix="$SCRIPTDIR/secp256k1/build/${OSARCH}" $SECP256K1_BUILD_OPTS && \
    make -j $CORE_COUNT && \
    make -j $CORE_COUNT install

  # Build the JNI ECRECOVER extension
  cat <<EOF
  ####################################
  ###### build secp256k1 JNI ########
  ####################################
EOF

  cd "$SCRIPTDIR/secp256k1/secp256k1_jni"
  
  # Ensure secp256k1 library is built first
  export SECP256K1_LIB_PATH="$SCRIPTDIR/secp256k1/bitcoin-core-secp256k1"
  
  # Clean and build
  make clean || true
  make
  
  # Copy results to build directory
  mkdir -p "$SCRIPTDIR/secp256k1/build/${OSARCH}/lib"
  if [[ "$OSTYPE" == "darwin"* ]]; then
    cp build/*/lib/libsecp256k1_ecrecover.dylib "$SCRIPTDIR/secp256k1/build/${OSARCH}/lib/"
  else
    cp build/*/lib/libsecp256k1_ecrecover.so "$SCRIPTDIR/secp256k1/build/${OSARCH}/lib/"
  fi
}

build_arithmetic() {
  cat <<EOF
  ##############################
  ###### build arithmetic ######
  ##############################
EOF

  cd "$SCRIPTDIR/arithmetic/arithmetic"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/arithmetic/build" || true
  mkdir -p "$SCRIPTDIR/arithmetic/build/lib"

  cargo clean

  if [[ "$OSTYPE" == "darwin"* ]];  then
    lipo_lib "libeth_arithmetic" ""
  else
    cargo build --lib --release
  fi

  mkdir -p "$SCRIPTDIR/arithmetic/build/${OSARCH}/lib"
  cp target/release/libeth_arithmetic.* "$SCRIPTDIR/arithmetic/build/${OSARCH}/lib"
}

build_ipa_multipoint() {
  cat <<EOF
  ##################################
  ###### build ipa_multipoint ######
  ##################################
EOF

  cd "$SCRIPTDIR/ipa-multipoint/ipa_multipoint_jni"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/ipa-multipoint/build" || true
  mkdir -p "$SCRIPTDIR/ipa-multipoint/build/${OSARCH}/lib"

  cargo clean

  if [[ "$OSARCH" == "darwin-x86-64" ]];  then
    cargo build --lib --release --target=x86_64-apple-darwin
    lipo -create \
      -output target/release/libipa_multipoint_jni.dylib \
      -arch x86_64 target/x86_64-apple-darwin/release/libipa_multipoint_jni.dylib
    lipo -info ./target/release/libipa_multipoint_jni.dylib
  elif [[ "$OSARCH" == "darwin-aarch64" ]]; then
    cargo build --lib --release --target=aarch64-apple-darwin
    lipo -create \
      -output target/release/libipa_multipoint_jni.dylib \
      -arch arm64 target/aarch64-apple-darwin/release/libipa_multipoint_jni.dylib
    lipo -info ./target/release/libipa_multipoint_jni.dylib
  else
    cargo build --lib --release
  fi

  mkdir -p "$SCRIPTDIR/ipa-multipoint/build/${OSARCH}/lib"
  cp target/release/libipa_multipoint_jni.* "$SCRIPTDIR/ipa-multipoint/build/${OSARCH}/lib"
}

build_jars(){
  ########################
  ###### build jars ######
  ########################

  if [[ "$SKIP_GRADLE" != "true" ]]; then
    cd $SCRIPTDIR
    ./gradlew build
  fi
}


lipo_lib() {
  cat <<EOF
  #################################################
  # multi-arch OSX universal binary build wrapper #
  #################################################
EOF
  LIBNAME=$1
  SWITCHES=$2

  # build both architectures
  cargo build --lib $SWITCHES --release --target=x86_64-apple-darwin
  cargo build --lib $SWITCHES --release --target=aarch64-apple-darwin

  lipo -create \
    -output target/release/$1.dylib \
    -arch x86_64 target/x86_64-apple-darwin/release/$1.dylib \
    -arch arm64 target/aarch64-apple-darwin/release/$1.dylib
}

build_secp256r1() {

  cat <<EOF
  #############################
  ###### build secp256r1 ######
  #############################
EOF

  cd "$SCRIPTDIR/secp256r1/besu-native-ec"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/secp256r1/build" || true
  find . -name *.o -exec rm -rf {} \;

  EXTRA_FLAGS=""
  if [[ "$OSTYPE" == "darwin"* ]]; then
    EXTRA_FLAGS="no-asm" # avoid assembly because of pipeline error
  fi

  OPENSSL_PLATFORM=""
  if [[ "$OSARCH" == "linux-gnu-aarch64" ]]; then
    OPENSSL_PLATFORM="linux-aarch64"
  fi


  git submodule init
  git submodule update

  cd openssl

  ./Configure $OPENSSL_PLATFORM no-shared -fPIC -fvisibility=hidden \
              enable-ec_nistp_64_gcc_128 no-stdio no-ocsp no-nextprotoneg no-module \
              no-legacy no-gost no-engine no-dynamic-engine no-deprecated no-comp \
              no-cmp no-capieng no-ui-console no-tls no-ssl no-dtls no-aria no-bf \
              no-blake2 no-camellia no-cast no-chacha no-cmac no-des no-dh no-dsa \
              no-ecdh no-idea no-md4 no-mdc2 no-ocb no-poly1305 no-rc2 no-rc4 no-rmd160 \
              no-scrypt no-seed no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool $EXTRA_FLAGS
  make build_generated libcrypto.a

  cd ../

  ./build.sh

  if [[ "$OSTYPE" == "darwin"* ]]; then
    lipo -info ./release/libbesu_native_ec.dylib
  fi

  mkdir -p "./release/${OSARCH}"
  echo `pwd`
  cp ./release/libbesu_native_ec* "./release/${OSARCH}/"

}

build_gnark() {
  cat <<EOF
  ############################
  ####### build gnark #######
  ############################
EOF

  cd "$SCRIPTDIR/gnark/gnark-jni"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/gnark/build" || true
  mkdir -p "$SCRIPTDIR/gnark/build/lib"

  if [[ "$OSTYPE" == "msys" ]]; then
    	LIBRARY_EXTENSION=dll
  elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIBRARY_EXTENSION=so
  elif [[ "$OSTYPE" == "darwin"* ]]; then
    LIBRARY_EXTENSION=dylib
    export GOROOT=$(brew --prefix go@1.25)/libexec
    export PATH=$GOROOT/bin:$PATH
  fi

  go build -buildmode=c-shared -o libgnark_jni.$LIBRARY_EXTENSION gnark-jni.go
  go build -buildmode=c-shared -o libgnark_eip_2537.$LIBRARY_EXTENSION gnark-eip-2537.go
  go build -buildmode=c-shared -o libgnark_eip_196.$LIBRARY_EXTENSION gnark-eip-196.go

  mkdir -p "$SCRIPTDIR/gnark/build/${OSARCH}/lib"
  cp libgnark_jni.* "$SCRIPTDIR/gnark/build/${OSARCH}/lib"
  cp libgnark_eip_2537.* "$SCRIPTDIR/gnark/build/${OSARCH}/lib"
  cp libgnark_eip_196.* "$SCRIPTDIR/gnark/build/${OSARCH}/lib"
}

build_constantine() {
  echo "#############################"
  echo "####### build constantine ####"
  echo "#############################"
  
  # don't try to build constantine on riscv64
  if [[ "$OSARCH" == "linux-gnu-riscv64" ]];  then
    return
  fi


  cd "$SCRIPTDIR/constantine/constantine"

  # delete old build dir, if exists
  rm -rf "$SCRIPTDIR/constantine/build" || true
  mkdir -p "$SCRIPTDIR/constantine/build/${OSARCH}/lib"

  # Check and modify config.nims if on x86_64
  if [[ "$OSARCH" == "linux-gnu-x86_64" ]]; then
    # Check if the config.nims already contains the necessary flags
    if ! grep -q 'switch("passC", "-fPIC")' config.nims; then
      {
        echo 'when defined(linux):'
        echo '  switch("passC", "-fPIC")'
        echo '  switch("passL", "-fPIC")'
      } >> config.nims
    fi
  fi

  # Build the constantine library
  export CTT_LTO=false
  if [[ "$OSARCH" == "linux-gnu-aarch64" ]]; then
    # Download and extract Nim
    wget https://github.com/nim-lang/nightlies/releases/download/2025-02-14-version-2-2-6c34f62785263ad412f662f3e4e4bf8d8751d113/nim-2.2.2-linux_arm64.tar.xz
    # verify download sha
    echo "d983fadd58afd78b0dda5f690b03bf0ba2ee034e3476f4c62cbbe352ffc4656b nim-2.2.2-linux_arm64.tar.xz" | sha256sum -c || exit 1
    tar -xf nim-2.2.2-linux_arm64.tar.xz
    git config --global --add safe.directory /home/ubuntu/constantine/constantine
    export PATH=$(pwd)/nim-2.2.2/bin:$PATH
    # arm64 ASM is currently only for apple silicon processors, revisit in future releases of constantine:
    export CTT_ASM=0
    nimble make_lib
  else
    export PATH=$HOME/.nimble/bin:$PATH
    nimble make_lib
  fi

  cd "$SCRIPTDIR/constantine/"

  # Compile the native library
 if [[ "$OSTYPE" == "darwin"* ]]; then
   # link against the static libconstantine.a so we do not have to deal with multiple libraries in jni/jna:
   clang -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/darwin" -shared -o "$SCRIPTDIR/constantine/build/${OSARCH}/lib/libconstantinebindings.dylib" jna_ethereum_evm_precompiles.c -Iconstantine/include -I. constantine/lib/libconstantine.a
 elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
   # link against the static libconstantine.a so we do not have to deal with multiple libraries in jni/jna:
   gcc -I"${JAVA_HOME}/include" -I"${JAVA_HOME}/include/linux" -fPIC -shared -o "$SCRIPTDIR/constantine/build/${OSARCH}/lib/libconstantinebindings.so" jna_ethereum_evm_precompiles.c -Iconstantine/include -I. -Lconstantine/lib constantine/lib/libconstantine.a
 else
   echo "Unsupported OS/architecture: ${OSARCH}"
   exit 1
 fi
}

build_boringssl() {

  cat <<EOF
  #############################
  ###### build boringssl ######
  #############################
EOF

  # build boring ssl static lib from submodule:
  cd "$SCRIPTDIR/boringssl/google-boringssl/"
  rm -rf build && mkdir build
  #-fPIC is redundant on macos, but required for building on linux
  cmake -B build -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_BUILD_TYPE=Release
  make -C build

  # build boringssl_jni shared lib linked against boringssl static lib
  cd "$SCRIPTDIR/boringssl/boringssl_jni/"
  make clean && make

  # copy the result into OSARCH specific directories, for CI
  mkdir -p "$SCRIPTDIR/boringssl/build/${OSARCH}/lib"
  cp build/libboringssl_precompiles.* "$SCRIPTDIR/boringssl/build/${OSARCH}/lib"
}


build_blake2bf
build_secp256k1
build_arithmetic
build_ipa_multipoint
build_secp256r1
build_gnark
build_constantine
build_boringssl

build_jars
exit
