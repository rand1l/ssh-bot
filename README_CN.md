<h1 align="center">
    <img src="img/logo.png" width="220" />
    <div>
    SSH Bot
    </div>
</h1>

<h4 align="center">
    <a href="README.md">English (🇺🇸)</a> | <a href="README_RU.md">Russian (🇷🇺)</a> | <strong> 中文 (🇨🇳)</strong> 
</h4>

一个 Telegram 机器人，允许您在家庭网络中的选定主机上运行指定命令，并实时返回其执行结果。该机器人与远程主机建立持久的 `SSH` 连接，从而可以实时执行长时间运行的命令，支持 `top` 等工具的伪终端（PTY），并能够停止正在运行的进程。内置的 `sftp` 支持可以方便地上传和下载文件。

该机器人为您节省了设置 `VPN` 服务器、静态 IP 地址或用于访问本地网络的 `VPS` 所需的时间和金钱。它还消除了在远程设备上使用第三方应用程序（如 `VPN` 和 `ssh` 客户端）的需要，并且不需要稳定的互联网连接。

<div align="center">

[https://github.com/user-attachments/assets/bca58846-55b4-4fec-a036-08c3eeb920aa](https://github.com/user-attachments/assets/bca58846-55b4-4fec-a036-08c3eeb920aa)

</div>

## 命令执行与交互性

  * [x] 在**本地**或**远程**（通过 SSH）环境中执行命令。
  * [x] 为长时间运行的命令（例如 `ping`、`tail`）提供**输出流**，并实时更新消息。
  * [x] 支持交互式程序（例如 `top`、`htop`）的**伪终端（PTY）**，并提供特殊的屏幕刷新模式（`/tty_refresh`）。
  * [x] 能够通过 Telegram 中的按钮**强制停止**正在运行的远程命令。
  * [x] 支持并行（异步）命令执行。
  * [x] 支持目录导航（`cd`）。

-----

## 文件管理 (SFTP)

  * [x] **上传文件**到远程服务器（`/upload`）。
  * [x] 从远程服务器直接**下载文件**到 Telegram 聊天（`/download`）。

-----

## SSH 连接管理

  * [x] **动态主机管理器**：添加（`/add_host`）和删除（`/del_host`）服务器，列表保存在 `hosts.json` 文件中。
  * [x] 通过**密钥**和/或**交互式密码提示**组合访问主机。
  * [x] 首次连接时进行交互式**主机密钥验证**，并能够将新密钥添加到 `known_hosts`。

-----

## 用户体验与界面

  * [x] 为长命令输出提供**分页**功能，并配有便捷的导航按钮。
  * [x] 自动**清除输出中的 ANSI 代码**（颜色），以实现干净可读的显示。
  * [x] 为需要交互式终端的命令提供优雅的错误处理。

## 启动

您可以从 [releases](https://github.com/rand1l/ssh-bot/releases) 页面下载预编译的可执行文件，并在本地运行该机器人。

> [\!NOTE]
> 启动前，您需要使用 [@BotFather](https://telegram.me/BotFather) 创建您的 Telegram 机器人并获取其 `API Token`，该 Token 必须在配置文件中指定。

  - 创建工作目录：

<!-- end list -->

```shell
mkdir ssh-bot
cd ssh-bot
```

  - 在工作目录中创建并填写 `.env` 文件：

<!-- end list -->

```shell
# 从 https://telegram.me/BotFather 获取的 Telegram API 密钥
TELEGRAM_BOT_TOKEN=XXXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# 从 https://t.me/getmyid_bot 获取的您的 Telegram ID
TELEGRAM_USER_ID=7777777777

# 仅在 Windows 本地运行机器人时使用的解释器
# 可用值：powershell/pwsh
WIN_SHELL=pwsh
# 在 Linux 本地和远程主机上使用的解释器
# 可用值：sh/bash/zsh 或其他
LINUX_SHELL=bash

# 并行（异步）执行命令（默认为 false）
PARALLEL_EXEC=true

# SSH 连接的全局参数（低优先级）
SSH_PORT=22
SSH_USER=rand1l

# 使用密码连接（可选）
SSH_PASSWORD=

# 容器内的私钥路径。
# 这告诉机器人在挂载后在哪里找到密钥。
# 重要提示：此路径必须与 docker-compose.yml 中卷挂载的右侧部分匹配。
# 对于本项目，它应始终为 '/root/.ssh/id_rsa'。
# 如果留空，机器人将使用此默认路径。
SSH_PRIVATE_KEY_PATH=
SSH_CONNECT_TIMEOUT=2

# 保存并重用传递的变量和函数（默认为 false）
SSH_SAVE_ENV=true

# 您主机上的私钥路径。
# docker-compose 使用此路径找到密钥并将其挂载到容器中。
SSH_PRIVATE_KEY_PATH_HOST=~/.ssh/id_rsa

# 记录命令执行的输出
LOG_MODE=DEBUG
# 用户个人 PIN 码的哈希值
PIN_HASH=
```

> [\!NOTE]
> 机器人的访问受用户 ID 限制。您可以使用 [@getmyid\_bot](https://t.me/getmyid_bot) 或在向机器人发送消息时在其日志中找到 Telegram `id`。

  - 在容器中运行机器人：

<!-- end list -->

```shell
docker run -d \
    --name ssh-bot \
    -v ./.env:/ssh-bot/.env \
    -v $HOME/.ssh/id_rsa:/root/.ssh/id_rsa \
    -v $HOME/.ssh/known_hosts:/ssh-bot/known_hosts \
    -v ./hosts.json:/ssh-bot/hosts.json \
    --restart unless-stopped \
    rand1l/ssh-bot:latest
```

> [\!NOTE]
> 机器人环境不存储在镜像中，而是使用挂载机制。要使用密钥访问远程主机，您需要将私钥文件从主机系统转发到容器中（如上例所示），并将 `SSH_PRIVATE_KEY_PATH` 变量的内容留空。

## 构建

```shell
git clone https://github.com/rand1l/ssh-bot
cd ssh-bot
cp .env.example .env
docker-compose up --build
```
