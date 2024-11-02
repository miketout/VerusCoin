The build was tested in the following environment: `macOS Monterey 12.6.1`.

```bash
sw_vers && xcodebuild -version && clang --version
...
ProductName:	macOS
ProductVersion:	12.6.1
BuildVersion:	21G217
Xcode 13.2.1
Build version 13C100
Apple clang version 13.0.0 (clang-1300.0.29.30)
Target: x86_64-apple-darwin21.6.0
Thread model: posix
InstalledDir: /Applications/Xcode_13.2.1.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin
```

#### OSX (Native)
Ensure you have [brew](https://brew.sh) and Command Line Tools installed.
```shell
# Install brew
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
# Install Xcode, opens a pop-up window to install CLT without installing the entire Xcode package
xcode-select --install 
# Update brew and install dependencies
brew update
brew upgrade
brew tap discoteq/discoteq; brew install flock
brew install autoconf autogen automake
brew install binutils
brew install protobuf
brew install coreutils
brew install wget


Get all that installed, then run:

```shell
git clone https://github.com/VerusCoin/VerusCoin.git
cd VerusCoin
./zcutil/build-mac.sh
./zcutil/fetch-params.sh
```

Happy Building

macOS 12 (Monterrey) have incompatible version of Xcode `14.2` (Build version 14C18), to build on Monterrey you'll need to install the older version `13.2.1` using the following steps:

- Download the specific Xcode 13.2.1 version from [here](https://stackoverflow.com/questions/10335747) or [here](https://developer.apple.com/services-account/download?path=/Developer_Tools/Xcode_13.2.1/Xcode_13.2.1.xip).
- [Install](https://stackoverflow.com/questions/43663097/how-to-install-xcode-from-xip-file) it.
- To set default Xcode version run this command:
```
sudo xcode-select -switch /Applications/Xcode_13.2.1.app
```
- To check default Xcode version in your system use this command:
```
xcodebuild -version
```
