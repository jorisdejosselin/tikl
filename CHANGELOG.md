# Changelog

## [0.3.0](https://github.com/jorisdejosselin/tikl/compare/tikl-v0.2.0...tikl-v0.3.0) (2026-09-07)


### Features

* --debug flag to dump the raw session stream (survives sudo) ([7fed6f5](https://github.com/jorisdejosselin/tikl/commit/7fed6f5e4e469ac55c2cb5caae5407074ec47383)), closes [#5](https://github.com/jorisdejosselin/tikl/issues/5)
* --upload sends files to the router over SSH/SFTP ([9bc3c9c](https://github.com/jorisdejosselin/tikl/commit/9bc3c9c931c9dc0673e13acb8ca2730ae3e0bd31))
* show the local interface a device was discovered on ([57352be](https://github.com/jorisdejosselin/tikl/commit/57352bec0f81ee5c9727ad5e42f926bf5941e5b4))
* TIKL_DEBUG=1 dumps the raw session byte stream to stderr ([dc068c0](https://github.com/jorisdejosselin/tikl/commit/dc068c037a022154523f803da8ff0ba834f2bf04)), closes [#5](https://github.com/jorisdejosselin/tikl/issues/5)


### Bug Fixes

* clear "needs sudo" message instead of a raw scapy traceback ([a209519](https://github.com/jorisdejosselin/tikl/commit/a209519764eb3d602117d84e5e7857f44c313e6e)), closes [#4](https://github.com/jorisdejosselin/tikl/issues/4)
* distinguish MAC-Telnet auth rejection from a silent login timeout ([9cbbac4](https://github.com/jorisdejosselin/tikl/commit/9cbbac49bc21863bf04aaaf31c970e6939924f84)), closes [#5](https://github.com/jorisdejosselin/tikl/issues/5)
* handle factory-fresh first-login prompts over MAC-Telnet ([1f9136b](https://github.com/jorisdejosselin/tikl/commit/1f9136b25d76d982024fdf21643e70a06866a46a)), closes [#5](https://github.com/jorisdejosselin/tikl/issues/5)

## [0.2.0](https://github.com/jorisdejosselin/tikl/compare/tikl-v0.1.0...tikl-v0.2.0) (2026-09-05)


### Features

* parallel interface auto-detect; hint to set --iface; silence scapy warning ([546a615](https://github.com/jorisdejosselin/tikl/commit/546a6159d7016c837246555ffabe22c2d79445a1))
* support TIKL_USER for the username (alongside TIKL_PASS) ([b575af0](https://github.com/jorisdejosselin/tikl/commit/b575af0b61927e2c7f818b64911d48ca9a9af2c0))


### Bug Fixes

* batch commands are fast and output is clean ([9e3215b](https://github.com/jorisdejosselin/tikl/commit/9e3215bac16ec147b521178433b15ee33b072d98))
* batch reports wide+tall terminal and dismisses RouterOS pager ([d85d928](https://github.com/jorisdejosselin/tikl/commit/d85d928e6e85aee067bee8b727ca6f2b159db61d))
* clear error instead of bare "Aborted!" when no password is available ([147fbdc](https://github.com/jorisdejosselin/tikl/commit/147fbdc4f2ad24012376def749ae09979303dc89))
* find and connect to routers on non-default interfaces ([408b34e](https://github.com/jorisdejosselin/tikl/commit/408b34e889c7b0d1a75c79a4a062172ac4311ee7))
* join unquoted command words; add -c; stop root .pyc writes ([80e1eac](https://github.com/jorisdejosselin/tikl/commit/80e1eaced1f79e46bfee055df5d9bcb777f91e8e))
* keep interactive sessions alive and always escapable ([2b697e1](https://github.com/jorisdejosselin/tikl/commit/2b697e12550a29c8470e2afadbe5052ec050a0e8))
* probe all interfaces during MNDP discovery ([8df7463](https://github.com/jorisdejosselin/tikl/commit/8df74634debd988883b195b30b997d6e43b031e0))
* report a wide+tall terminal in batch so output never paginates ([27e3194](https://github.com/jorisdejosselin/tikl/commit/27e31945ad1f4b89460a79cb21b0618545ecfd76))


### Documentation

* cross-OS install one-liners (uv/git, binaries, Docker) + MAC prereqs ([3e77399](https://github.com/jorisdejosselin/tikl/commit/3e77399b5ef995d316e42f186ad1bb4b182e89e3))

## 0.1.0 (2026-09-02)


### Features

* initial Tikl implementation — MAC-Telnet + SSH recovery CLI ([7854ffd](https://github.com/jorisdejosselin/tikl/commit/7854ffdecf7087ed8edd93cc967091d04be56356))
