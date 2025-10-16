# Windows 11 家庭版 SMB 访问高级修复工具

仅保留并维护“高级修复工具”：`Fix-SMBAccess-Advanced.ps1` 与其启动器 `启动高级修复工具.bat`。

本工具面向 Windows 11 家庭版，聚焦解决共享目录访问问题，尤其是错误代码 `0x80004005` 与凭据认证异常。无任何 Web 相关操作。

## 功能概述
- 网络连通性与端口测试：验证 `Ping` 与 `TCP 445`（SMB）可用性。
- 凭据清理与重建：删除错误凭据，支持添加正确的用户名/密码。
- 高级 SMB 客户端设置：可放宽安全签名与访客登录以兼容老设备。
- 可选 SMB1 兼容：在需要时尝试启用（可能在部分版本上受限）。
- 网络服务与缓存刷新：清理映射、刷新 DNS/NetBIOS，提高重新连接成功率。

## 文件结构
- `Fix-SMBAccess-Advanced.ps1`：高级修复脚本（核心）。
- `启动高级修复工具.bat`：批处理启动器（双击运行）。

## 系统要求
- Windows 11 家庭版（Windows 10 亦可尝试）。
- 管理员权限运行 PowerShell。
- PowerShell 5.0 及以上。

## 快速开始
- 方式一：双击 `启动高级修复工具.bat`（推荐，中文提示）。
- 方式二：以管理员权限打开 PowerShell，执行：
  - 交互式：`./Fix-SMBAccess-Advanced.ps1`
  - 指定参数：`./Fix-SMBAccess-Advanced.ps1 -TargetIP "192.168.31.119" -Username "用户名" -Password "密码"`

## 参数说明
- `-TargetIP`：目标共享设备的 IP 地址（如 `192.168.31.119`）。
- `-Username`：用于访问共享的用户名（本地账户或 `域\用户名`）。
- `-Password`：该用户的密码。
- `-AutoFix`：存在时按提供参数自动执行（可选）。

## 常见使用示例
- 交互式修复（用户逐步确认）：
  - `./Fix-SMBAccess-Advanced.ps1`
- 指定本地用户：
  - `./Fix-SMBAccess-Advanced.ps1 -TargetIP "192.168.31.119" -Username "admin" -Password "P@ssw0rd"`
- 指定域用户：
  - `./Fix-SMBAccess-Advanced.ps1 -TargetIP "192.168.31.119" -Username "MYDOMAIN\user" -Password "secret"`

## 修复后如何重新连接共享
- 删除旧映射并重建：
  - `net use * /delete /y`
  - `net use \\192.168.31.119\共享名 /user:用户名 密码`
- 或在资源管理器地址栏输入：`\\192.168.31.119` 按回车后选择共享。

## 日志位置
- 默认日志：`%TEMP%\SMB-Advanced-Fix-Log.txt`。
- 排查问题时可附上该日志内容。

## 故障排查（0x80004005 等）
- 检查端口 445：`Test-NetConnection 192.168.31.119 -Port 445`
- 清除错误凭据：
  - `net use * /delete /y`
  - 打开“凭据管理器”删除相关网络凭据（或脚本自动处理）。
- 再次添加正确凭据：
  - `net use \\192.168.31.119\共享名 /user:用户名 密码`
- 若设备较旧（NAS/路由器），可能需要 SMB1 兼容；脚本会尽量启用，但某些版本/版本策略可能不支持。

## 注意事项（安全与兼容）
- SMB1 存在安全风险，仅在必须时启用；建议内网使用并保持设备更新。
- 放宽“访客登录”“禁用安全签名”等仅用于兼容性与故障定位，完成后可恢复更安全的配置。
- 如果目标设备需要特定权限或账户策略，请使用正确的本地/域账户格式（如 `device\user` 或 `domain\user`）。

## 贡献与反馈
- 欢迎提交 Issue 反馈使用中遇到的问题。
- 如需贡献代码，请按照现有风格与结构提交 PR（仅针对高级工具）。

## 许可
- 建议使用 MIT 许可。你也可以根据项目需要替换为其他许可。

---

本仓库不包含任何 Web 相关内容；仅提供 Windows 端 SMB 访问修复工具及其批处理启动器。