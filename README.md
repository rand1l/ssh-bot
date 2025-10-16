<h1 align="center">
    <img src="img/logo.png" width="220" />
    <div>
    SSH Bot
    </div>
</h1>

<h4 align="center">
    <strong>English (🇺🇸)</strong> | <a href="README_RU.md">Russian (🇷🇺)</a>
</h4>

A Telegram bot that allows you to run specified commands on a selected host in your home network and returns the results of their execution in real time. The bot establishes a persistent `SSH` connection with the remote host, which allows for the real-time execution of long-running commands, with pseudo-terminal (PTY) support for utilities like top and the ability to stop running processes. Built-in `sftp` support allows for easy uploading and downloading of files.

The bot saves you the time and money required to set up a `VPN` server, a static IP address, or a `VPS` for local network access. It also eliminates the need for third-party applications (like `VPN` and `ssh` clients) on a remote device and does not require a stable internet connection.

<div align="center">

https://github.com/user-attachments/assets/bca58846-55b4-4fec-a036-08c3eeb920aa

</div>

## Command Execution & Interactivity

* [x] Executing commands in a **local** or **remote** (via SSH) environment.
* [x] **Output streaming** for long-running commands (e.g., `ping`, `tail`) with real-time message updates.
* [x] **Pseudo-terminal (PTY) support** for interactive programs (e.g., `top`, `htop`) with a special screen refresh mode (`/tty_refresh`).
* [x] Ability to **forcibly stop** running remote commands via a button in Telegram.
* [x] Support for parallel (asynchronous) command execution.
* [x] Support for directory navigation (`cd`).

---

## File Management (SFTP)

* [x] **Uploading files** to the remote server (`/upload`).
* [x] **Downloading files** from the remote server directly to the Telegram chat (`/download`).

---

## SSH Connection Management

* [x] **Dynamic host manager**: adding (`/add_host`) and deleting (`/del_host`) servers with the list persisted in a `hosts.json` file.
* [x] Combined access to hosts via **key** and/or an **interactive password prompt**.
* [x] Interactive **host key verification** on the first connection, with the ability to add new keys to `known_hosts`.

---

## User Experience & Interface

* [x] **Pagination** for long command outputs with convenient navigation buttons.
* [x] Automatic **cleaning of output from ANSI codes** (colors) for a clean and readable display.
* [x] Graceful error handling for commands that require an interactive terminal.



## Launch

You can download the pre-compiled executable from the [releases](https://github.com/rand1l/ssh-bot/releases) page and run the bot locally.

> [!NOTE]
> Before launching, you need to create your Telegram bot using [@BotFather](https://telegram.me/BotFather) and get its `API Token`, which must be specified in the configuration file.

- Create a working directory:

```shell
mkdir ssh-bot
cd ssh-bot
```

- Create and fill the `.env` file file inside the working directory:

```shell
# Telegram api key from https://telegram.me/BotFather
TELEGRAM_BOT_TOKEN=XXXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# Your Telegram id from https://t.me/getmyid_bot
TELEGRAM_USER_ID=7777777777

# Interpreter used only when running the bot local in Windows
# Available values: powershell/pwsh
WIN_SHELL=pwsh
# Interpreter used on local and remote hosts in Linux
# Available values: sh/bash/zsh or other
LINUX_SHELL=bash

# Parallel (async) execution of commands (default: false)
PARALLEL_EXEC=true

# Global parameters for ssh connection (low priority)
SSH_PORT=22
SSH_USER=rand1l

# Use password to connect (optional)
SSH_PASSWORD=

# Path to the private key INSIDE THE CONTAINER.
# This tells the bot where to find the key after it has been mounted.
# IMPORTANT: This path MUST match the right side of the volume mount in docker-compose.yml.
# For this project, it should always be '/root/.ssh/id_rsa'.
# If you leave this empty, the bot will use this default path.
SSH_PRIVATE_KEY_PATH=
SSH_CONNECT_TIMEOUT=2

# Save and reuse passed variables and functions (default: false)
SSH_SAVE_ENV=true

# Path to the private key ON YOUR HOST MACHINE.
# This is used by docker-compose to find the key and mount it into the container.
SSH_PRIVATE_KEY_PATH_HOST=~/.ssh/id_rsa

# Log the output of command execution
LOG_MODE=DEBUG
# User personal PIN hash
PIN_HASH=
```

> [!NOTE]
> Access to the bot is limited by user ID. You can find out the Telegram `id` using [@getmyid_bot](https://t.me/getmyid_bot) or in the bot logs when sending a message to it.

- Run the bot in a container:

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

> [!NOTE]
> The bot environment is not stored in an image, but uses a mounting mechanism. To access remote hosts using a key, you need to forward the private key file from the host system to the container (as in the example above) and leave the contents of the `SSH_PRIVATE_KEY_PATH` variable empty.

## Build

```shell
git clone https://github.com/rand1l/ssh-bot
cd ssh-bot
cp .env.example .env
docker-compose up --build
```
