# Changelog

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
