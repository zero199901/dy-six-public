# dy-six-public

当前仓库已切到新版抖音包链路抖音6神新设备号注册，后续更新纯算版本 基于：

- APK：`106_859156870953e1de6eff681e0baa17f8.apk`
- `versionName`：`38.8.0`
- `versionCode`：`380801`
- so：`_tmp_new_libmetasec_ml.so`

抖音 tiktok  unidbg版本 纯算python版本
<img width="1188" height="1572" alt="image" src="https://github.com/user-attachments/assets/fd89d789-a4b1-4bc6-8fbe-4e875a7ed1cd" />
## 当前状态

已适配新版初始化与签名流程：

- `load_module(..., True)`
- `JNI_OnLoad`
- `ms.bd.c.k.a / ms.bd.c.f3.a`
- 最终签名主 opcode：`33554438`

当前 `/api/sign` 默认直接返回：

- `X-Argus`
- `X-Gorgon`
- `X-Helios`
- `X-Khronos`
- `X-Ladon`
- `X-Medusa`

如果最终头未取到，代码会回退返回 raw frameSign 字段：

- `frametype`
- `lid`
- `signinfo`
- `signvalue`
- `signversion`

`X-Khan` 已定位到独立 opcode，但当前未默认挂到主接口。

## 环境

- 推荐 Python：`3.11.x`

安装依赖：

```bash
pip install -r requirements.txt
```

## 启动

运行：

```bash
python server.py
```

默认监听：

```text
http://127.0.0.1:8899
```

## API

请求：

```http
POST /api/sign
Content-Type: application/json
```

请求体示例：

```json
{
  "url": "https://api5-normal-lf.amemv.com/aweme/v1/...",
  "header": {
    "Cookie": "...",
    "x-tt-dt": "...",
    "x-tt-token": "...",
    "user-agent": "com.ss.android.ugc.aweme/380801 (...)"
  }
}
```

成功响应示例：

```json
{
  "X-Argus": "...",
  "X-Gorgon": "...",
  "X-Helios": "...",
  "X-Khronos": "...",
  "X-Ladon": "...",
  "X-Medusa": "..."
}
```

## 本地测试

- 启动服务后可直接运行：`python main.py`
- 示例请求文件：`1.json`

## device_register 工具链

新增的现场抓包 / 回放工具都在 `tools/`：

- `run-frida.cmd`：一键拉起 `tools/run-frida.ps1`
- `tools/run-frida.ps1`：自动 clear app、拉起 frida、抓首包、抽取 response
- `tools/device_register_live.py`：现场构包 + TTEncrypt + 直提 `device_register`
- `tools/device_register_suite.py`：批量构造 payload / 回放 / 变体测试
- `tools/device_register_random.py`：随机设备标识与可通过的硬件画像同步
- `tools/extract_device_register_ttencrypt.py`：从 frida 日志抽首个 `ss_app_log`
- `tools/extract_device_register_response.py`：从 frida 日志抽有效 `device_register_response`

常用命令：

```powershell
run-frida.cmd
python tools\device_register_live.py --random-device --out-dir tools\_live_random_fixed2
python tools\device_register_live.py --random-hardware-profile --random-device --out-dir tools\_live_hw_profile_ids_seed7
```

说明：

- `tools/_*`、`tools/ab_*`、`logs/` 都是本地实验输出，默认不进 git
- “全随机硬件画像”当前已收敛为“随机真实硬件画像 + 保留 runtime OS 版本”
- 实测 `os_version / os_api` 改动会导致 `device_id=0 / install_id=0`

## 这次适配包含的关键修复

- 新版 opcode 适配到 `33554438`
- 保留 raw frameSign 回退
- JNI object 返回值本地引用封装
- `Boolean.valueOf / Integer.valueOf / Long.valueOf` 补齐
- arm64 `getppid / geteuid / getgid / getegid` syscall 补齐
- `/proc/stat` stub 与高频噪音日志清理
  - 频率限制/风控，稍后重试或更换网络。
- 如果返回非 JSON（HTML/重定向/验证码等），请查看测试脚本打印的 `status`、`content-type` 与正文预览，通常是参数或会话失效导致。

---

如果这个项目对你有帮助，欢迎 Star。仅供学习参考，切勿用于非法用途。
