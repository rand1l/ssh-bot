package env

import (
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Env struct {
	TELEGRAM_BOT_TOKEN   string
	TELEGRAM_USER_ID     int64
	WIN_SHELL            string
	LINUX_SHELL          string
	PARALLEL_EXEC        bool
	SSH_PORT             string
	SSH_USER             string
	SSH_PASSWORD         string
	SSH_PRIVATE_KEY_PATH string
	SSH_CONNECT_TIMEOUT  string
	SSH_SAVE_ENV         bool
	SSH_HOSTS            string
	LOG_MODE             string
	SshHostsMap          map[string]string
	PIN_HASH             string
}

func (env *Env) GetEnv() {
	data, err := os.ReadFile(".env")
	// Check reading of env file
	if err != nil {
		// If .env doesn't exist, we just proceed with defaults, no need to crash
		if os.IsNotExist(err) {
			log.Println("[WARN] .env file not found, using default values and environment variables.")
		} else {
			log.Fatal(err)
		}
	}
	// Get array strings from file
	dataString := strings.TrimSpace(string(data))
	lines := strings.Split(dataString, "\n")

	// Remove comments and lines that do not match key=value
	var linesNotComments []string
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		} else if strings.Contains(line, "=") {
			linesNotComments = append(linesNotComments, line)
		}
	}

	// Fill the environment
	for _, line := range linesNotComments {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		envKey := strings.TrimSpace(parts[0])
		envValue := strings.TrimSpace(parts[1])

		switch {
		case envKey == "TELEGRAM_BOT_TOKEN":
			env.TELEGRAM_BOT_TOKEN = strings.TrimSpace(strings.Split(envValue, "#")[0])
		case envKey == "TELEGRAM_USER_ID":
			TELEGRAM_USER_ID_STR := strings.TrimSpace(strings.Split(envValue, "#")[0])
			TELEGRAM_USER_ID_INT, _ := strconv.ParseInt(TELEGRAM_USER_ID_STR, 10, 64)
			env.TELEGRAM_USER_ID = TELEGRAM_USER_ID_INT
		case envKey == "WIN_SHELL":
			env.WIN_SHELL = strings.TrimSpace(strings.Split(envValue, "#")[0])
		case envKey == "LINUX_SHELL":
			env.LINUX_SHELL = strings.TrimSpace(strings.Split(envValue, "#")[0])
		case envKey == "PARALLEL_EXEC":
			checkType := strings.ToLower(strings.TrimSpace(strings.Split(envValue, "#")[0]))
			if checkType == "true" {
				env.PARALLEL_EXEC = true
			} else {
				env.PARALLEL_EXEC = false
			}
		case envKey == "SSH_PORT":
			env.SSH_PORT = strings.TrimSpace(strings.Split(envValue, "#")[0])
		case envKey == "SSH_USER":
			env.SSH_USER = strings.TrimSpace(strings.Split(envValue, "#")[0])
		case envKey == "SSH_PASSWORD":
			env.SSH_PASSWORD = strings.TrimSpace(strings.Split(envValue, "#")[0])
		case envKey == "SSH_PRIVATE_KEY_PATH":
			env.SSH_PRIVATE_KEY_PATH = strings.TrimSpace(strings.Split(envValue, "#")[0])
		case envKey == "SSH_CONNECT_TIMEOUT":
			env.SSH_CONNECT_TIMEOUT = strings.TrimSpace(strings.Split(envValue, "#")[0])
		case envKey == "SSH_SAVE_ENV":
			checkType := strings.ToLower(strings.TrimSpace(strings.Split(envValue, "#")[0]))
			if checkType == "true" {
				env.SSH_SAVE_ENV = true
			} else {
				env.SSH_SAVE_ENV = false
			}
		case envKey == "LOG_MODE":
			env.LOG_MODE = strings.TrimSpace(strings.Split(envValue, "#")[0])
		case envKey == "PIN_HASH":
			env.PIN_HASH = strings.TrimSpace(strings.Split(envValue, "#")[0])
		}
	}

	// Fill the default environment
	if len(env.WIN_SHELL) == 0 {
		env.WIN_SHELL = "powershell"
	}
	if len(env.LINUX_SHELL) == 0 {
		env.LINUX_SHELL = "sh"
	}
	if len(env.SSH_PORT) == 0 {
		env.SSH_PORT = "22"
	}
	if len(env.SSH_USER) == 0 {
		env.SSH_USER = "root"
	}
	if len(env.SSH_PRIVATE_KEY_PATH) == 0 {
		var envPath string
		if runtime.GOOS == "windows" {
			envPath = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		} else {
			envPath = os.Getenv("HOME")
		}
		env.SSH_PRIVATE_KEY_PATH = envPath + "/.ssh/id_rsa"
	}
	if len(env.SSH_CONNECT_TIMEOUT) == 0 {
		env.SSH_CONNECT_TIMEOUT = "2"
	}
}

func (env *Env) PrintEnv() {
	log.Println()
	log.Println("[ENV] TELEGRAM_BOT_TOKEN: " + env.TELEGRAM_BOT_TOKEN)
	log.Printf("[ENV] TELEGRAM_USER_ID: %d \n", env.TELEGRAM_USER_ID)
	log.Println("[ENV] WIN_SHELL: " + env.WIN_SHELL)
	log.Println("[ENV] LINUX_SHELL: " + env.LINUX_SHELL)
	log.Printf("[ENV] PARALLEL_EXEC: %t\n", env.PARALLEL_EXEC)
	log.Println("[ENV] SSH_PORT: " + env.SSH_PORT)
	log.Println("[ENV] SSH_USER: " + env.SSH_USER)
	log.Println("[ENV] SSH_PASSWORD: " + env.SSH_PASSWORD)
	log.Println("[ENV] SSH_PRIVATE_KEY_PATH: " + env.SSH_PRIVATE_KEY_PATH)
	log.Println("[ENV] SSH_CONNECT_TIMEOUT: " + env.SSH_CONNECT_TIMEOUT)
	log.Printf("[ENV] SSH_SAVE_ENV: %t\n", env.SSH_SAVE_ENV)

	if env.PIN_HASH != "" {
		log.Println("[ENV] PIN_HASH: <set>")
	} else {
		log.Println("[ENV] PIN_HASH: <not set>")
	}

	log.Println("[ENV] SSH_HOSTS (from hosts.json):")
	if len(env.SshHostsMap) > 0 {
		for alias, connStr := range env.SshHostsMap {
			log.Printf("[ENV] - %s -> %s\n", alias, connStr)
		}
	} else {
		log.Println("[ENV] - No hosts loaded.")
	}
	log.Println()
}
