# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - TBA

### Added

- This BurpSuite extensions allows the automatic creation and deletion of upstream SOCKS5 proxy on popular cloud services.
- Initial release supports multiple providers: AWS, Digital Ocean and Linode.
- Each provider has its unique settings, including region selection.
- Automatically destroy proxy when closing Burp or unloading the extension, with the option to preserve the proxy across sessions instead.
- When proxy is destroyed, restore SOCKS5 proxy settings in Burp to their original values.
- Compatibility across multiple devices, ensuring seamless use without interference from proxies generated on separate computers.

[unreleased]: https://github.com/d3mondev/burp-vps-proxy/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/d3mondev/burp-vps-proxy/releases/tag/v1.0.0
