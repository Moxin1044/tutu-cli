# 发布说明

本文档说明如何把 `tutu-vuln-intel` 发布到 PyPI。默认使用 **GitHub Trusted Publishing（OIDC）**，不需要在 GitHub 中保存 PyPI Token。

## 1. 首次配置 PyPI Trusted Publisher

首次发布前，在 PyPI 添加一个 **pending publisher**：

1. 登录 <https://pypi.org/>
2. 打开 <https://pypi.org/manage/account/publishing/>
3. 选择 “Add a new pending publisher”
4. 填写：

| 字段 | 值 |
| --- | --- |
| PyPI Project Name | `tutu-vuln-intel` |
| Owner | `Moxin1044` |
| Repository name | `tutu` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

保存后，`release.yml` 第一次成功运行时会自动创建 PyPI 项目。

> 如果项目已经存在，则到项目页的 “Publishing” 设置中添加同样的 Trusted Publisher。

## 2. 创建 GitHub Environment

仓库已默认使用名为 `pypi` 的 environment。首次发布前可以在 GitHub 仓库中确认：

`Settings → Environments → New environment → pypi`

也可以不手动创建，GitHub Actions 首次使用时会自动创建。

## 3. 发布新版本

1. 修改 `pyproject.toml` 中的 `version`
2. 更新 `CHANGELOG.md`
3. 提交并推送
4. 创建并推送 tag：

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "release: v0.1.0"
git push origin main
git tag v0.1.0
git push origin v0.1.0
```

推送 tag 后，`Release` workflow 会：

1. 构建 sdist + wheel
2. `twine check` 校验元数据
3. 通过 OIDC 发布到 PyPI
4. 创建 GitHub Release 并附带构建产物

发布完成后验证：

```bash
pip install -U tutu-vuln-intel
tutu --version
```

## 4. 如果 Trusted Publishing 暂不可用

可以在 GitHub 仓库中添加 Secret：

```text
PYPI_API_TOKEN = pypi-...   # PyPI API Token
```

然后把 `release.yml` 中的发布步骤改为：

```yaml
- name: Publish package distributions to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    packages-dir: dist/
    password: ${{ secrets.PYPI_API_TOKEN }}
```

不要把 Token 提交到仓库，也不要写进 `pyproject.toml`。

## 5. 包名说明

- PyPI 发行名：`tutu-vuln-intel`
- 安装后命令：`tutu`

```bash
pip install tutu-vuln-intel
tutu -v CVE-2026
```
