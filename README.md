# swbom

从 requirements.txt、npm package-lock.json 或简单依赖清单生成轻量 CycloneDX 风格 SBOM。它不联网解析仓库，先把软件组成、版本和来源在本地构建出来，再交给漏洞扫描或合规流水线。

使用：python swbom.py examples/requirements.txt -o sbom.json，或指定 examples/package-lock.json。

车载软件供应链越来越长，版本、来源和许可证信息如果只存在构建机上，很难支撑漏洞响应和 R155 证据。先生成稳定的机器可读清单，可以作为更完整 SBOM 管理的基础。

## 许可证

MIT
