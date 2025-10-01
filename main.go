package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"net"
	"errors"

	env "github.com/rand1l/ssh-bot/pkg/env"

	sshClient "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"


	api "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

var pendingHostKeyVerifications = make(map[int64]chan bool)
var pendingPasswordRequests = make(map[int64]chan string)

type SSH struct {
	PWD             string
	SSH_MODE        bool
	SSH_HOST        string
	SSH_USER        string
	SSH_PORT        string
	SSH_PRIVATE_KEY []byte
	Client          *sshClient.Client
}

// Get parameters for ssh connection from env
func (ssh *SSH) paramParse(host string, env *env.Env) (string, string, string) {
	var userName, port string
	if strings.Contains(host, "@") {
		hostSplit := strings.Split(host, "@")
		userName = hostSplit[0]
		host = hostSplit[1]
	} else {
		userName = env.SSH_USER
	}
	if strings.Contains(host, ":") {
		hostSplit := strings.Split(host, ":")
		port = hostSplit[1]
		host = hostSplit[0]
	} else {
		port = env.SSH_PORT
	}
	return host, userName, port
}

// Change directory on localhost
func (ssh *SSH) localChangeDir(bot *api.BotAPI, chatID int64, message string) {
	newPath := strings.TrimSpace(message[3:])
	err := os.Chdir(newPath)
	if err != nil {
		msg := api.NewMessage(chatID, "⚠ Error changing directory:\n\n```Go\n"+err.Error()+"```")
		msg.ParseMode = api.ModeMarkdown
		bot.Send(msg)
		log.Printf("[ERROR] Error changing directory: %s", err.Error())
		return
	}
	pwd, _ := os.Getwd()
	msg := api.NewMessage(chatID, "Current directory:\n\n`"+pwd+"`")
	msg.ParseMode = api.ModeMarkdown
	bot.Send(msg)
	log.Printf("[INFO] Current directory: %s", pwd)
}


func (ssh *SSH) sshConnect(env *env.Env, bot *api.BotAPI, chatID int64) error {
	// If a client is already connected, close the old connection first.
	if ssh.Client != nil {
		ssh.Client.Close()
		ssh.Client = nil
	}

	knownHostsPath := "/ssh-bot/known_hosts"

	// Initialize the known_hosts callback from the file.
	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		log.Printf("[ERROR] Could not load known_hosts file: %v", err)
		return fmt.Errorf("could not load known_hosts file: %w", err)
	}

	// This is our custom host key verification logic.
	// It's a closure to capture the 'bot' and 'chatID' variables.
	var customHostKeyCallback sshClient.HostKeyCallback = func(hostname string, remote net.Addr, key sshClient.PublicKey) error {
		// First, check if the key is already in our known_hosts file.
		err := hostKeyCallback(hostname, remote, key)

		// Case 1: Key is known and matches. No error.
		if err == nil {
			log.Printf("[INFO] Host key for %s is known and matches.", hostname)
			return nil
		}

		// An error occurred. Let's find out what kind.
		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			// Case 3: A key for this host is known, but it DOES NOT MATCH.
			// This is a potential man-in-the-middle attack. Abort!
			if len(keyErr.Want) > 0 {
				log.Printf("[CRITICAL] HOST KEY MISMATCH for %s! Aborting connection.", hostname)
				return fmt.Errorf("host key mismatch: possible man-in-the-middle attack")
			}
			// Case 2: The key is simply NOT FOUND in the file. This is normal for a first-time connection.
			// We proceed to ask the user for confirmation.
		} else {
			// This is some other unexpected error (e.g., file permissions). Abort.
			log.Printf("[ERROR] Unexpected error during host key verification: %v", err)
			return err
		}

		// Ask the user for verification.
		log.Printf("[WARN] Unknown host key for %s. Asking user for verification.", hostname)

		decisionChan := make(chan bool)
		pendingHostKeyVerifications[chatID] = decisionChan

		fingerprint := sshClient.FingerprintSHA256(key)
		messageText := fmt.Sprintf(
			"⚠️ The authenticity of host '%s' can't be established.\n\n"+
				"Key fingerprint is `%s`.\n\n"+
				"Are you sure you want to continue connecting?",
			hostname,
			fingerprint,
		)

		yesButton := api.NewInlineKeyboardButtonData("✅ Yes", "verify_host_yes")
		noButton := api.NewInlineKeyboardButtonData("❌ No", "verify_host_no")
		keyboard := api.NewInlineKeyboardMarkup(api.NewInlineKeyboardRow(yesButton, noButton))
		msg := api.NewMessage(chatID, messageText)
		msg.ParseMode = api.ModeMarkdown
		msg.ReplyMarkup = keyboard
		bot.Send(msg)

		// Block execution until we get a response from the user.
		decision := <-decisionChan
		delete(pendingHostKeyVerifications, chatID)

		if !decision {
			return fmt.Errorf("host key verification rejected by user")
		}

		// User agreed. Add the new key to our known_hosts file.
		f, ferr := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if ferr != nil {
			return fmt.Errorf("could not open known_hosts to add new key: %w", ferr)
		}
		defer f.Close()

		// Ensure the file ends with a newline before appending a new key.
		stat, _ := f.Stat()
		if stat.Size() > 0 {
			buf := make([]byte, 1)
			f.ReadAt(buf, stat.Size()-1)
			if buf[0] != '\n' {
				f.WriteString("\n")
			}
		}

		// Append the new key in the correct format.
		newLine := knownhosts.Line([]string{hostname}, key)
		if _, ferr = f.WriteString(newLine + "\n"); ferr != nil {
			return fmt.Errorf("could not write new key to known_hosts: %w", ferr)
		}
		log.Printf("[INFO] Added new host key for %s to known_hosts.", hostname)
		return nil
	}

	// This is our handler for interactive password prompts.
	keyboardInteractiveChallenge := func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		if len(questions) == 0 {
			return nil, nil
		}

		passwordChan := make(chan string)
		pendingPasswordRequests[chatID] = passwordChan

		prompt := fmt.Sprintf("Enter password for `%s@%s`:", user, ssh.SSH_HOST)
		if len(questions) > 0 {
			prompt = fmt.Sprintf("%s\n\n```\n%s\n```", prompt, strings.Join(questions, "\n"))
		}
		msg := api.NewMessage(chatID, prompt)
		msg.ParseMode = api.ModeMarkdown
		bot.Send(msg)

		// Block and wait for the user to type the password.
		password := <-passwordChan
		delete(pendingPasswordRequests, chatID)

		return []string{password}, nil
	}

	// Get signer from private key.
	signer, err := sshClient.ParsePrivateKey(ssh.SSH_PRIVATE_KEY)
	if err != nil {
		log.Printf("[ERROR] Could not parse private key: %v", err)
		return fmt.Errorf("could not parse private key: %w", err)
	}

	// Convert timeout param.
	timeoutSeconds, _ := strconv.Atoi(env.SSH_CONNECT_TIMEOUT)
	timeoutDuration := time.Duration(timeoutSeconds) * time.Second

	// Assemble the final SSH client configuration.
	config := &sshClient.ClientConfig{
		User:            ssh.SSH_USER,
		HostKeyCallback: customHostKeyCallback,
		Timeout:         timeoutDuration,
		Auth: []sshClient.AuthMethod{
			// 1. Try public key authentication first.
			sshClient.PublicKeys(signer),
			// 2. If that fails, try an interactive password prompt.
			sshClient.KeyboardInteractive(keyboardInteractiveChallenge),
			// 3. As a last resort, use the non-interactive password from .env (if provided).
			sshClient.Password(env.SSH_PASSWORD),
		},
	}

	log.Printf("[DEBUG] Dialing tcp to %s:%s...", ssh.SSH_HOST, ssh.SSH_PORT)
	client, err := sshClient.Dial("tcp", fmt.Sprintf("%s:%s", ssh.SSH_HOST, ssh.SSH_PORT), config)
	if err != nil {
		log.Printf("[ERROR] Failed to dial: %v", err)
		return fmt.Errorf("failed to dial: %w", err)
	}
	log.Println("[DEBUG] TCP connection established.")

	// Success! Store the active client in our struct.
	ssh.Client = client
	return nil
}

// Run command via a persistent SSH connection
func (ssh *SSH) sshRunCommand(command string) ([]byte, error) {
	// Проверяем, есть ли у нас активный клиент
	if ssh.Client == nil {
		return nil, errors.New("ssh client is not connected")
	}
	
	// Create a new session from an existing client
	session, err := ssh.Client.NewSession()
	if err != nil {
		// If the session could not be created, the connection may have been lost.
		// Reconnection logic can be added here.
		log.Printf("[ERROR] Failed to create session: %v", err)
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	var out bytes.Buffer
	session.Stdout = &out
	session.Stderr = &out

	err = session.Run(command)
	return out.Bytes(), err
}
// Run command on local or remote host
func (ssh *SSH) runCommand(env *env.Env, bot *api.BotAPI, update api.Update, chatID int64, messageText string) {
	var output []byte
	var err error
	var SHELL string
	if ssh.SSH_MODE {
		var command string
		// Import declare from temp file
		if env.SSH_SAVE_ENV {
			command = "[ -e /tmp/ssh-bot.temp ] && source /tmp/ssh-bot.temp; "
		}
		// Change directory + run command
		command = command + "cd " + ssh.PWD + " && " + messageText
		// Export declare in temp file
		if env.SSH_SAVE_ENV {
			command = command + " && declare -p | grep '^declare -- ' > /tmp/ssh-bot.temp; declare -f >> /tmp/ssh-bot.temp"
		}
		output, err = ssh.sshRunCommand(command)
	} else {
		if runtime.GOOS == "windows" {
			SHELL = env.WIN_SHELL
		} else {
			SHELL = env.LINUX_SHELL
		}
		output, err = exec.Command(SHELL, "-c", messageText).CombinedOutput()
	}
	var out string
	if ssh.SSH_MODE {
		out = "`" + ssh.SSH_HOST + "`\n```" + env.LINUX_SHELL + "\n" + string(output) + "```"
	} else {
		// Update shell for Markdown
		if SHELL == "pwsh" {
			SHELL = "powershell"
		}
		out = "`localhost`\n```" + SHELL + "\n" + string(output) + "```"
	}
	if err != nil {
		out = "⚠ " + out
		msg := api.NewMessage(chatID, out)
		msg.ReplyToMessageID = update.Message.MessageID
		msg.ParseMode = api.ModeMarkdown
		bot.Send(msg)
		log.Printf("[ERROR] Execution error on %s: %s", ssh.SSH_HOST, string(output))
	} else {
		out = "▶ " + out
		msg := api.NewMessage(chatID, out)
		msg.ReplyToMessageID = update.Message.MessageID
		msg.ParseMode = api.ModeMarkdown
		bot.Send(msg)
		if env.LOG_MODE == "DEBUG" {
			if ssh.SSH_MODE {
				log.Printf("[DEBUG] Response from %v:", ssh.SSH_HOST)
			} else {
				log.Printf("[DEBUG] Response from localhost:")
			}
			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			for _, line := range lines {
				log.Printf("[DEBUG] %s", line)
			}
		}
	}
}

func main() {
	log.Println("[INFO] Bot started")

	env := &env.Env{}
	env.GetEnv()

	if env.TELEGRAM_BOT_TOKEN == "" || env.TELEGRAM_BOT_TOKEN == "XXXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" {
		log.Fatal("❌ FATAL: TELEGRAM_BOT_TOKEN is not set or contains a placeholder value. Please check your .env file.")
	}
	if env.TELEGRAM_USER_ID == 0 {
		log.Fatal("❌ FATAL: TELEGRAM_USER_ID is not set. Please check your .env file.")
	}
	if env.TELEGRAM_USER_ID == 7777777777 {
		log.Println("⚠️ WARNING: TELEGRAM_USER_ID is set to the default example value. Please check your .env file.")
	}

	ssh := &SSH{}

	// Read private key
	ssh.SSH_PRIVATE_KEY, _ = os.ReadFile(env.SSH_PRIVATE_KEY_PATH)

	bot, err := api.NewBotAPI(env.TELEGRAM_BOT_TOKEN)
	if err != nil {
		log.Fatal(err)
	}

	u := api.NewUpdate(0)
	u.Timeout = 30
	updates := bot.GetUpdatesChan(u)

	// Main menu
	commands := []api.BotCommand{
		{Command: "host_list", Description: "List of hosts for ssh connection"},
		{Command: "exit", Description: "Disconnect from the remote host and clear the declared environment"},
	}
	_, err = bot.Request(api.NewSetMyCommands(commands...))
	if err != nil {
		log.Printf("[ERROR] %s", string(err.Error()))
	}

	for update := range updates {
		// Get parameters from message/menu and callback query (keyboard)
		var chatID int64
		var firstName string
		var lastName string
		var userName string
		var messageText string
		switch {
		case update.Message != nil:
			chatID = update.Message.Chat.ID
			firstName = update.Message.Chat.FirstName
			lastName = update.Message.Chat.LastName
			userName = update.Message.Chat.UserName
			messageText = update.Message.Text

			if passwordChan, ok := pendingPasswordRequests[chatID]; ok {
				// Send the entered text to the waiting goroutine
				passwordChan <- messageText

				// Delete the password message from the chat for security reasons
				deleteRequest := api.NewDeleteMessage(chatID, update.Message.MessageID)
				bot.Request(deleteRequest)
				
				// Optional: Send confirmation that the password has been received
				confirmMsg := api.NewMessage(chatID, " `Password received, authenticating...`")
				confirmMsg.ParseMode = api.ModeMarkdown
				bot.Send(confirmMsg)

				continue // Finish processing this message
			}
		
		case update.CallbackQuery != nil:
			chatID = update.CallbackQuery.Message.Chat.ID
			firstName = update.CallbackQuery.From.FirstName
			lastName = update.CallbackQuery.From.LastName
			userName = update.CallbackQuery.From.UserName
			messageText = update.CallbackQuery.Data

			// check whether this callback is a response to key verification.
			if decisionChan, ok := pendingHostKeyVerifications[chatID]; ok {
				var decision bool
				if messageText == "verify_host_yes" {
					decision = true
					// Edit the message so the user can see the result
					bot.Send(api.NewEditMessageText(chatID, update.CallbackQuery.Message.MessageID, "✅ Host key accepted. Continuing connection..."))
				} else { // "verify_host_no"
					decision = false
					bot.Send(api.NewEditMessageText(chatID, update.CallbackQuery.Message.MessageID, "❌ Host key rejected. Aborting connection."))
				}
				
				// Send the response (true/false) to the waiting goroutine
				decisionChan <- decision

				// Respond to the callback to remove the "clock" on the button
				bot.Request(api.NewCallback(update.CallbackQuery.ID, ""))
				
				// Aborting further processing of this update
				continue
			}

			// If this wasn't a validation response, click the button from /host_list,
			// simply respond to the callback and let the code move on,
			// to process messageText as a command (/ssh ...)
			_, err = bot.Request(api.NewCallback(update.CallbackQuery.ID, ""))
			if err != nil {
				log.Printf("[ERROR] %s", string(err.Error()))
			}
		default:
			continue
		}

		// Access check
		if chatID != env.TELEGRAM_USER_ID {
			bot.Send(api.NewMessage(chatID, "⛔ Access denied ⛔"))
			log.Printf("[WARN] Unauthorized access from %s %s (%s - %d)", firstName, lastName, userName, chatID)
			continue
		}

		log.Printf("[INFO] Request from %s %s (%s - %d): %s", firstName, lastName, userName, chatID, messageText)

		// Disconnect from ssh and clear declared environment (remove temp file)
		if messageText == "/exit" || messageText == "exit" {
			if ssh.SSH_MODE {
				// First, run any cleanup commands using the existing connection
				if env.SSH_SAVE_ENV {
					// This command is fire-and-forget, so we ignore potential errors
					ssh.sshRunCommand("rm /tmp/ssh-bot.temp")
				}

				// IMPORTANT: Properly close the persistent SSH client connection
				if ssh.Client != nil {
					ssh.Client.Close()
					ssh.Client = nil // Clear the client from the struct
				}
				
				// Reset the state
				ssh.SSH_MODE = false
				
				// Notify the user
				messageOutput := api.NewMessage(chatID, "Disconnected from `"+ssh.SSH_HOST+"`")
				messageOutput.ParseMode = api.ModeMarkdown
				bot.Send(messageOutput)
				log.Println("[INFO] Disconnected from " + ssh.SSH_HOST)
			} else {
				bot.Send(api.NewMessage(chatID, "Remote connection not established"))
				log.Println("[INFO] Remote connection not established")
			}
			continue
		}
		// Send keyboard buttons from host list
		if messageText == "/host_list" {
			var keyboardButton [][]api.InlineKeyboardButton
			for _, host := range env.SSH_HOST_LIST {
				btn := api.NewInlineKeyboardButtonData(host, "/ssh "+host)
				keyboardButton = append(keyboardButton, []api.InlineKeyboardButton{btn})
			}
			keyboard := api.NewInlineKeyboardMarkup(keyboardButton...)
			msg := api.NewMessage(chatID, "Select host to ssh connection:")
			msg.ReplyMarkup = keyboard
			bot.Send(msg)
			continue
		}

		// Switch to selected host via ssh
		if strings.HasPrefix(messageText, "/ssh") {
			// We launch the entire connection logic in a separate goroutine
			// to avoid blocking the main loop while waiting for user input (host key/password).
			go func() {
				selectedHost := strings.TrimSpace(strings.Replace(messageText, "/ssh", "", 1))
				if len(selectedHost) == 0 {
					messageOutput := api.NewMessage(chatID, "Host name not specified\n\nPass the host name as a parameter, for example: `/ssh 192.168.1.1`")
					messageOutput.ParseMode = api.ModeMarkdown
					bot.Send(messageOutput)
					log.Println("[ERROR] Host name not specified")
					return // Use return as we are inside a new function
				}
				
				// We parse connection parameters first
				ssh.SSH_HOST, ssh.SSH_USER, ssh.SSH_PORT = ssh.paramParse(selectedHost, env)
				
				// Send a temporary "Connecting..." message to the user
				sendMessage, _ := bot.Send(api.NewMessage(chatID, "Connecting to "+selectedHost+"..."))
				lastMessageID := sendMessage.MessageID
				log.Println("[INFO] Connection to " + selectedHost)

				// Call our new dedicated connection function
				err := ssh.sshConnect(env, bot, chatID)

				// Check for connection errors
				if err != nil {
					ssh.SSH_MODE = false // Ensure SSH mode is off on failure
					detailedError := err.Error()
					msgText := "⚠ Connection error to " + selectedHost + "\n\n" + "```Error\n" + detailedError + "```"
					editMessage := api.NewEditMessageText(chatID, lastMessageID, msgText)
					editMessage.ParseMode = api.ModeMarkdown
					bot.Send(editMessage)
					log.Println("[ERROR] Connection error: " + detailedError)
					return
				}

				// --- Connection Successful ---
				ssh.SSH_MODE = true // Set SSH mode only AFTER a successful connection
				log.Println("[INFO] Connection successful to " + selectedHost)

				// Get system info to display to the user
				output, err := ssh.sshRunCommand("uname -a")
				if err != nil {
					log.Printf("[WARN] Failed to run 'uname -a' after connect: %v", err)
				}

				// Update the temporary message with the success status and system info
				msgText := "✅ Connection successful to " + selectedHost + "\n\n" + "```Info\n" + string(output) + "```"
				editMessage := api.NewEditMessageText(chatID, lastMessageID, msgText)
				editMessage.ParseMode = api.ModeMarkdown
				bot.Send(editMessage)

				// Get the initial present working directory (pwd)
				output, err = ssh.sshRunCommand("pwd")
				if err != nil {
					log.Printf("[WARN] Failed to run 'pwd' after connect: %v", err)
				}
				ssh.PWD = strings.TrimSpace(string(output))

			}() // End of goroutine
			continue
		}

		// Change directory
		if strings.HasPrefix(messageText, "cd ") {
			// Get path via ssh
			if ssh.SSH_MODE {
				command := "cd " + ssh.PWD + " && " + messageText + " && pwd"
				output, err := ssh.sshRunCommand(command)
				if err != nil {
					msg := api.NewMessage(chatID, "⚠ Error changing directory:\n\n```ssh\n"+string(output)+"```")
					msg.ParseMode = api.ModeMarkdown
					bot.Send(msg)
					log.Printf("[ERROR] Error changing directory: %s", string(output))
					continue
				}
				ssh.PWD = strings.TrimSpace(string(output))
				msg := api.NewMessage(chatID, "Current directory:\n\n`"+ssh.PWD+"`")
				msg.ParseMode = api.ModeMarkdown
				bot.Send(msg)
				log.Printf("[INFO] Current directory: %s", ssh.PWD)
			} else {
				// Change local directory via os library
				ssh.localChangeDir(bot, chatID, messageText)
			}
			continue
		}

		// Run command for execution
		if env.PARALLEL_EXEC {
			go ssh.runCommand(env, bot, update, chatID, messageText)
		} else {
			ssh.runCommand(env, bot, update, chatID, messageText)
		}
	}
}
