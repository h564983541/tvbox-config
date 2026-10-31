# tvbox-config

合并后的 TVBox 配置，每小时自动更新一次（抓取各源的最新配置，合并去重）。

## 电视里填这个地址（主）

https://cdn.jsdelivr.net/gh/h564983541/tvbox-config@main/config.json

## 备用地址

- https://cdn.statically.io/gh/h564983541/tvbox-config/main/config.json
- https://raw.githubusercontent.com/h564983541/tvbox-config/main/config.json

## 说明

- 源列表在 `sources.json`，合并脚本是 `merge.py`，规则：站点按 key 去重、蜘蛛 JAR 按源补齐、直播与解析按名称+地址去重。
- 本仓库只包含公开源的公开配置，不含任何密钥。
