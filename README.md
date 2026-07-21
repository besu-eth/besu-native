# Besu Native

This repository contains scripts and tooling that is used to build and package the native libraries
used by Hyperledger Besu.

Besu Native libraries are licensed unde the [Apache 2.0 License](LICENSE).

## Prerequisites

### Linux

You'll need to be sure that gcc, make, autoconf, automake, and libtool are installed. If you are
building on Ubuntu or Debian, the following command will install these dependencies for you:

```
sudo apt-get install build-essential automake autoconf libtool cmake
```

### OS X

You'll need to be sure that XCode Command Line Tools, make, autoconf, automake, and libtool are
installed. The easiest way to do this is to install [Homebrew](https://brew.sh/), and then run the
following command. Note that installing Homebrew will automatically install the XCode command line
tools.

```
brew install autoconf automake libtool
```

### Windows

TBD


## Language tools

Additionally you will need golang, rust, and nim.  Distributions often do not have the latest
versions of these languages.  Check for latest builds:
https://www.rust-lang.org/tools/install
https://go.dev/dl/
https://nim-lang.org/install.html

### Golang

Golang is required to compile the gnark-based libraries for all platforms and architectures.  

On MacOs, homebrew has a working golang target, e.g.:

`brew install go`

on Linux, for most recent distributions there is typically a somewhat recent go package, e.g.
`apt install go`

You can fetch the latest golang distribution here:
https://go.dev/dl/

### Nim

Nim 2.2.x+ is required to build Constantine.  Constantine is skipped on riscv64 architectures, so it is not needed for linux-riscv64.
On MacOs, homebrew has a working nim target, e.g.:

`brew install nim`

on Linux, for most recent distributions there is typically a nim package, e.g. 
`apt install nim`

Otherwise see:
https://nim-lang.org/install.html

### Rust

Rust needs to be installed to compile the arithmetic library. The default way to install it on Linux or OS X is:

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

If you are Mac M1/M2/M3 you might need to add this after installing rust:

```
rustup target add x86_64-apple-darwin
```

If you prefer another installation method please refer to the [Rust installation instructions](https://www.rust-lang.org/tools/install).

## Building

1. This repository builds native libraries from source that is included as git submodules. To be
   sure that you have cloned those submodules into the appropriate locations,
   run `git submodule init && git submodule update`
2. The build steps are entirely contained within the `build.sh` script at the repository root.
   Simply run this script, and all the native modules contained herein will be configured with the
   correct build options for Hyperledger Besu, and built.

