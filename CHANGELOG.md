# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Experimental SSH provider that enables the use of a remote SSH connection as a SOCKS5 proxy. It does the equivalent of `ssh -D` but from within the VPS Proxy tab. Only password authentication supported for the moment.

### Changed
- Provider base class now has a close() method that is called on the current provider whenever the extension is unloaded, whether the provider is active or not.
- Provider base class now has a onRestore() method that is called when the extension is loaded and the provider is active.

## [1.0.0] - 2023-04-03

### Added

- Automatic creation, configuration and deletion of upstream SOCKS5 proxy on popular cloud services from within BurpSuite.
- Support for multiple providers: AWS, Digital Ocean and Linode.
- Each provider has its unique settings, including region selection.
- Automatic destruction of proxy when closing Burp or unloading the extension, with an option to preserve the proxy across sessions instead.
- Restores SOCKS5 proxy settings in Burp to their original values when the proxy is destroyed.
- Compatibility across multiple devices, ensuring seamless use without interference from proxies generated on separate computers.

[unreleased]: https://github.com/d3mondev/burp-vps-proxy/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/d3mondev/burp-vps-proxy/releases/tag/v1.0.0
