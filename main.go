package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	env "github.com/rand1l/ssh-bot/pkg/env"

	api "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/pkg/sftp"
	sshClient "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var pendingHostKeyVerifications = make(map[int64]chan bool)
var pendingPasswordRequests = make(map[int64]chan string)

// maps a message ID to a running SSH session.
// used to stop long-running commands via a callback button.
var activeSessions = make(map[int]*sshClient.Session)
var activeSessionsMutex = &sync.Mutex{}

// stores the destination path for a file upload that was initiated
// by the /upload command. The key is the chat ID.
// It is protected by a mutex to handle concurrent messages safely.var pendingUploads = make(map[int64]string)
var pendingUploads = make(map[int64]string)
var pendingUploadsMutex = &sync.Mutex{}

var sshHosts = make(map[string]string)
var sshHostsMutex = &sync.RWMutex{}
const hostsFilePath = "/ssh-bot/hosts.json"

// Used to strip ANSI escape codes (e.g., color codes, cursor movements)
// from the command output to get clean text for Telegram.
var ansiRegex = regexp.MustCompile("[\u001B\u009B][[\\]()#;?]*((([a-zA-Z\\d]*(;[a-zA-Z\\d]*)*)?\u0007)|((\\d{1,4}(;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))")

type PagedMessage struct {
	Pages       []string // Slice with prepared pages
	Header   string // Message header (status + host)
	CurrentPage   int    // Current page for paginated output
	Follow   bool   // Whether to follow the output (auto-scroll)
}

var pagedMessages = make(map[int]PagedMessage)
var pagedMessagesMutex = &sync.Mutex{}
const pageLen = 4000

// SSH holds the state and client for a persistent SSH connection.
type SSH struct {
    PWD             string
    SSH_MODE        bool
    SSH_HOST        string
    SSH_USER        string
    SSH_PORT        string
    SSH_PRIVATE_KEY []byte
    Client          *sshClient.Client
}

const maxFileSize = 48 * 1024 * 1024 //	48MB


// maxOutputBufferSize defines the maximum size of the command output buffer in bytes (1024 KB).
// This prevents a single command from consuming excessive memory and overwhelming the Telegram API.
const maxOutputBufferSize = 1024 * 1024

func handleAddHost(bot *api.BotAPI, chatID int64, text string) {
	parts := strings.Fields(text)
	if len(parts) != 3 {
		bot.Send(api.NewMessage(chatID, "Usage: `/add_host <alias> <user@host:port>`"))
		return
	}
	alias := parts[1]
	connectionString := parts[2]

	sshHostsMutex.Lock()
	defer sshHostsMutex.Unlock()

	sshHosts[alias] = connectionString

	// Save the updated list to a file
	data, err := json.MarshalIndent(sshHosts, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed to marshal hosts to JSON: %v", err)
		bot.Send(api.NewMessage(chatID, "❌ Error saving host list."))
		return
	}

	err = os.WriteFile(hostsFilePath, data, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to write to hosts.json: %v", err)
		bot.Send(api.NewMessage(chatID, "❌ Error saving host list to file."))
		return
	}

	bot.Send(api.NewMessage(chatID, fmt.Sprintf("✅ Host '%s' was added.", alias)))
	log.Printf("[INFO] Host '%s' added.", alias)
}

func handleDelHost(bot *api.BotAPI, chatID int64, text string) {
	parts := strings.Fields(text)
	if len(parts) != 2 {
		bot.Send(api.NewMessage(chatID, "Usage: `/del_host <alias>`"))
		return
	}
	alias := parts[1]

	sshHostsMutex.Lock()
	defer sshHostsMutex.Unlock()

	if _, ok := sshHosts[alias]; !ok {
		bot.Send(api.NewMessage(chatID, fmt.Sprintf("❌ Host '%s' not found.", alias)))
		return
	}

	delete(sshHosts, alias)

	// Save the updated list to a file
	data, err := json.MarshalIndent(sshHosts, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed to marshal hosts to JSON: %v", err)
		bot.Send(api.NewMessage(chatID, "❌ Error saving host list."))
		return
	}

	err = os.WriteFile(hostsFilePath, data, 0644)
	if err != nil {
		log.Printf("[ERROR] Failed to write to hosts.json: %v", err)
		bot.Send(api.NewMessage(chatID, "❌ Error saving host list to file."))
		return
	}

	bot.Send(api.NewMessage(chatID, fmt.Sprintf("✅ Host '%s' was deleted.", alias)))
	log.Printf("[INFO] Host '%s' deleted.", alias)
}

// Handles downloading a file from the server to Telegram
func (ssh *SSH) handleFileDownload(bot *api.BotAPI, chatID int64, remotePath string) {
	if !ssh.SSH_MODE || ssh.Client == nil {
		bot.Send(api.NewMessage(chatID, "Error: An active SSH connection is required to download files."))
		return
	}

	// Send a placeholder message
	placeholder, _ := bot.Send(api.NewMessage(chatID, fmt.Sprintf("⏳ Downloading `%s`...", remotePath)))

	// Create an SFTP client
	sftpClient, err := sftp.NewClient(ssh.Client)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Error creating SFTP client: %v", err)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		log.Printf("[ERROR] SFTP client creation failed: %v", err)
		return
	}
	defer sftpClient.Close()

	// Check file size before reading
	stat, err := sftpClient.Stat(remotePath)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to get file info for `%s`: %v", remotePath, err)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		return
	}
	if stat.Size() > maxFileSize {
		errorMsg := fmt.Sprintf("❌ File is too large: %.2f MB. Limit: %.2f MB.", float64(stat.Size())/1024/1024, float64(maxFileSize)/1024/1024)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		return
	}
	if stat.IsDir() {
		errorMsg := fmt.Sprintf("❌ The specified path `%s` is a directory, not a file.", remotePath)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		return
	}

	// Open the remote file
	remoteFile, err := sftpClient.Open(remotePath)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to open remote file `%s`: %v", remotePath, err)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		log.Printf("[ERROR] Remote file open failed: %v", err)
		return
	}
	defer remoteFile.Close()

	// Read the file content
	fileBytes, err := io.ReadAll(remoteFile)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Error reading file `%s`: %v", remotePath, err)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		log.Printf("[ERROR] File read failed: %v", err)
		return
	}

	// Send the document to Telegram
	doc := api.FileBytes{
		Name:  stat.Name(),
		Bytes: fileBytes,
	}
	msg := api.NewDocument(chatID, doc)
	msg.Caption = fmt.Sprintf("✅ File `%s` downloaded successfully.", remotePath)
	msg.ParseMode = api.ModeMarkdown

	bot.Send(msg)
	// Delete the placeholder
	bot.Request(api.NewDeleteMessage(chatID, placeholder.MessageID))
	log.Printf("[INFO] File downloaded successfully: %s", remotePath)
}

// Manages the process of receiving a document from Telegram
// and uploading it to the remote server via SFTP. It requires a pending
// upload state to be set by the /upload command first.
func (ssh *SSH) handleFileUpload(bot *api.BotAPI, update api.Update) {
	chatID := update.Message.Chat.ID
	doc := update.Message.Document
	
	// Check for a pending upload path from the /upload command
	pendingUploadsMutex.Lock()
	remotePath, isPending := pendingUploads[chatID]
	if isPending {
		// Clear the pending state immediately to prevent re-uploading the next file
		delete(pendingUploads, chatID)
	}
	pendingUploadsMutex.Unlock()

	// If no upload was initiated with the /upload command, reject the file.
	if !isPending {
		bot.Send(api.NewMessage(chatID, "❌ Error: To upload a file, you must first specify the destination path with the command:\n`/upload /path/to/destination`\nand attach the file in a subsequent message."))
		return
	}

	// General checks
	if !ssh.SSH_MODE || ssh.Client == nil {
		bot.Send(api.NewMessage(chatID, "Error: An active SSH connection is required to upload files."))
		return
	}
	if doc.FileSize > maxFileSize {
		bot.Send(api.NewMessage(chatID, fmt.Sprintf("❌ File is too large: %.2f MB. Limit: %.2f MB.", float64(doc.FileSize)/1024/1024, float64(maxFileSize)/1024/1024)))
		return
	}

	placeholder, _ := bot.Send(api.NewMessage(chatID, fmt.Sprintf("⏳ Uploading file to server at `%s`...", remotePath)))

	// Get a direct URL for the file
	fileURL, err := bot.GetFileDirectURL(doc.FileID)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to get file link: %v", err)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		log.Printf("[ERROR] Failed to get file URL: %v", err)
		return
	}

	// Download the file from Telegram's servers
	resp, err := http.Get(fileURL)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to download file from Telegram servers: %v", err)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		log.Printf("[ERROR] Failed to download file from Telegram: %v", err)
		return
	}
	defer resp.Body.Close()

	// Create an SFTP client
	sftpClient, err := sftp.NewClient(ssh.Client)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Error creating SFTP client: %v", err)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		log.Printf("[ERROR] SFTP client creation failed: %v", err)
		return
	}
	defer sftpClient.Close()

	// Create the file on the remote server
	dstFile, err := sftpClient.Create(remotePath)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Failed to create file on server at `%s`: %v", remotePath, err)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		log.Printf("[ERROR] Failed to create remote file: %v", err)
		return
	}
	defer dstFile.Close()

	// Copy the content to the remote file
	bytesCopied, err := io.Copy(dstFile, resp.Body)
	if err != nil {
		errorMsg := fmt.Sprintf("❌ Error writing data to file `%s`: %v", remotePath, err)
		bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
		log.Printf("[ERROR] Failed to write to remote file: %v", err)
		return
	}

	successMsg := fmt.Sprintf("✅ File `%s` (%.2f MB) uploaded successfully.", remotePath, float64(bytesCopied)/1024/1024)
	bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, successMsg))
	log.Printf("[INFO] File uploaded successfully to %s", remotePath)
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

// Establishes a persistent SSH connection to a remote host.
// It handles key-based authentication, interactive password prompts, and host key verification.
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
            // This is a potential man-in-the-middle attack. Abort
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
        msg.ReplyMarkup = &keyboard
        bot.Send(msg)

        // Block execution until we get a response from the user
        decision := <-decisionChan
        delete(pendingHostKeyVerifications, chatID)

        if !decision {
            return fmt.Errorf("host key verification rejected by user")
        }

        // User agreed. Add the new key to our known_hosts file
        f, ferr := os.OpenFile(knownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
        if ferr != nil {
            return fmt.Errorf("could not open known_hosts to add new key: %w", ferr)
        }
        defer f.Close()

        // Ensure the file ends with a newline before appending a new key
        stat, _ := f.Stat()
        if stat.Size() > 0 {
            buf := make([]byte, 1)
            f.ReadAt(buf, stat.Size()-1)
            if buf[0] != '\n' {
                f.WriteString("\n")
            }
        }

        // Append the new key in the correct format
        newLine := knownhosts.Line([]string{hostname}, key)
        if _, ferr = f.WriteString(newLine + "\n"); ferr != nil {
            return fmt.Errorf("could not write new key to known_hosts: %w", ferr)
        }
        log.Printf("[INFO] Added new host key for %s to known_hosts.", hostname)
        return nil
    }

    // handles password prompts from the SSH server
	// by asking the user for input in Telegram.
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

        // Block and wait for the user to type the password
        password := <-passwordChan
        delete(pendingPasswordRequests, chatID)

        return []string{password}, nil
    }

    signer, err := sshClient.ParsePrivateKey(ssh.SSH_PRIVATE_KEY)
    if err != nil {
        log.Printf("[ERROR] Could not parse private key: %v", err)
        return fmt.Errorf("could not parse private key: %w", err)
    }

    timeoutSeconds, _ := strconv.Atoi(env.SSH_CONNECT_TIMEOUT)
    timeoutDuration := time.Duration(timeoutSeconds) * time.Second

    // Assemble the final SSH client configuration.
    config := &sshClient.ClientConfig{
        User:            ssh.SSH_USER,
        HostKeyCallback: customHostKeyCallback,
        Timeout:         timeoutDuration,
        Auth: []sshClient.AuthMethod{
            sshClient.PublicKeys(signer),			// 1. Try public key authentication first.
            sshClient.KeyboardInteractive(keyboardInteractiveChallenge),	// 2. Try interactive password prompt.
            sshClient.Password(env.SSH_PASSWORD),	// 3. Try non-interactive password from .env.
        },
    }

    log.Printf("[DEBUG] Dialing tcp to %s:%s...", ssh.SSH_HOST, ssh.SSH_PORT)
    client, err := sshClient.Dial("tcp", fmt.Sprintf("%s:%s", ssh.SSH_HOST, ssh.SSH_PORT), config)
    if err != nil {
        log.Printf("[ERROR] Failed to dial: %v", err)
        return fmt.Errorf("failed to dial: %w", err)
    }
    log.Println("[DEBUG] TCP connection established.")

    ssh.Client = client
    return nil
}

// Executes a command and returns the output without streaming.
// It's used for internal commands like 'pwd' or 'uname'.
func (ssh *SSH) sshRunSimpleCommand(command string) ([]byte, error) {
    if ssh.Client == nil {
        return nil, errors.New("ssh client is not connected")
    }

    session, err := ssh.Client.NewSession()
    if err != nil {
        log.Printf("[ERROR] Failed to create session for simple command: %v", err)
        return nil, fmt.Errorf("failed to create session: %w", err)
    }
    defer session.Close()
    
    // Use CombinedOutput to get both stdout and stderr
    output, err := session.CombinedOutput(command)
    if err != nil {
        log.Printf("[ERROR] Simple command failed: %v. Output: %s", err, string(output))
        return output, err
    }

    return output, nil
}

// Creates the inline keyboard with "Up", "Page X/Y", and "Down" buttons
// It disables buttons by replacing them with a blank placeholder when at the start or end of the output
func getPaginationKeyboard(messageID int, currentPage int, totalPages int) *api.InlineKeyboardMarkup {
    var row []api.InlineKeyboardButton

    if currentPage > 0 {
        row = append(row, api.NewInlineKeyboardButtonData("⬆️ Up", fmt.Sprintf("page_up_%d", messageID)))
    } else {
        row = append(row, api.NewInlineKeyboardButtonData(" ", "noop"))
    }

    pageIndicator := api.NewInlineKeyboardButtonData(fmt.Sprintf("%d / %d", currentPage+1, totalPages), "noop")
    row = append(row, pageIndicator)

    if currentPage < totalPages-1 {
        row = append(row, api.NewInlineKeyboardButtonData("⬇️ Down", fmt.Sprintf("page_down_%d", messageID)))
    } else {
        row = append(row, api.NewInlineKeyboardButtonData(" ", "noop"))
    }

    keyboard := api.NewInlineKeyboardMarkup(row)
    return &keyboard
}

// buildPages breaks large text into pages, preserving line integrity.
func buildPages(fullText string, maxPageLen int) []string {
    lines := strings.Split(fullText, "\n")
    if len(lines) == 1 && len(lines[0]) == 0 {
        return []string{""} // Return one empty page if there is no output
    }

    var pages []string
    var pageBuilder strings.Builder

    for _, line := range lines {
		// Check if adding a newline will exceed the page limit
		// +1 is needed for the line break character '\n'
        if pageBuilder.Len()+len(line)+1 > maxPageLen {
            // The current page is full, save it
            pages = append(pages, pageBuilder.String())
            pageBuilder.Reset()
        }

        // Add a line and wrap to a new line
        pageBuilder.WriteString(line)
        pageBuilder.WriteString("\n")
    }

    // Add the last, unfilled page, if there is one
    if pageBuilder.Len() > 0 {
        pages = append(pages, pageBuilder.String())
    }
    
    // If after all operations there are no pages (for example, the input string was empty)
    if len(pages) == 0 {
        return []string{""}
    }

    return pages
}

func sendOrEditFinalMessage(bot *api.BotAPI, chatID int64, messageID int, header string, cleanedOutput string) {
    // Clean up any previous pagination state for this message to prevent memory leaks
    pagedMessagesMutex.Lock()
    delete(pagedMessages, messageID)
    pagedMessagesMutex.Unlock()

    pages := buildPages(cleanedOutput, pageLen)


    if len(cleanedOutput) > pageLen {
		// Long output: set up a new pagination state.
        pagedMessagesMutex.Lock()
        pagedMessages[messageID] = PagedMessage{
            Pages:       pages,
            Header:      header,
            CurrentPage: 0,
            Follow:      false,
        }
        pagedMessagesMutex.Unlock()

        firstPageContent := pages[0]
        
        keyboard := getPaginationKeyboard(messageID, 0, len(pages))

        finalText := header + "```sh\n" + firstPageContent + "```"
        finalEdit := api.NewEditMessageText(chatID, messageID, finalText)
        finalEdit.ParseMode = api.ModeMarkdown
        finalEdit.ReplyMarkup = keyboard
        bot.Request(finalEdit)

    } else {
		// Short output. Send as is and remove any previous buttons (like "Stop").
        finalText := header
        if len(cleanedOutput) > 0 {
            finalText += "```sh\n" + cleanedOutput + "```"
        }
        
        finalEdit := api.NewEditMessageText(chatID, messageID, finalText)
        finalEdit.ParseMode = api.ModeMarkdown
        finalEdit.ReplyMarkup = &api.InlineKeyboardMarkup{InlineKeyboard: [][]api.InlineKeyboardButton{}}
        bot.Request(finalEdit)
    }
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// runCommand is the core function for executing commands, handling both SSH and local execution.
// It features logic to differentiate between short and long-running commands for a better UX.
func (ssh *SSH) runCommand(env *env.Env, bot *api.BotAPI, chatID int64, messageText string, requestPTY bool, isRefreshMode bool) {
	if ssh.SSH_MODE {
		command := "cd " + ssh.PWD + " && " + messageText

		placeholderText := fmt.Sprintf("▶️ Executing on `%s`...", ssh.SSH_HOST)
		msg, err := bot.Send(api.NewMessage(chatID, placeholderText))
		if err != nil {
			log.Printf("[ERROR] Failed to send initial message: %v", err)
			return
		}
		messageID := msg.MessageID

		if ssh.Client == nil {
			editMsg := api.NewEditMessageText(chatID, messageID, "⚠ Error: SSH client is not connected.")
			editMsg.ParseMode = api.ModeMarkdown
			bot.Request(editMsg)
			return
		}
		session, err := ssh.Client.NewSession()
		if err != nil {
			editMsg := api.NewEditMessageText(chatID, messageID, fmt.Sprintf("⚠ Error: Failed to create session: %v", err))
			editMsg.ParseMode = api.ModeMarkdown
			bot.Request(editMsg)
			return
		}
		defer session.Close()

		// Request a pseudo-terminal (PTY) if the user specified /tty or /tty_refresh.
		// This is necessary for interactive programs like 'top' or for getting colored output.
		if requestPTY {
			log.Println("[INFO] PTY requested by user.")
			modes := sshClient.TerminalModes{
				sshClient.ECHO:          0,
				sshClient.TTY_OP_ISPEED: 14400,
				sshClient.TTY_OP_OSPEED: 14400,
			}
			if err := session.RequestPty("xterm", 1000, 150, modes); err != nil {
				log.Printf("[ERROR] Request for PTY failed: %v", err)
				editMsg := api.NewEditMessageText(chatID, messageID, fmt.Sprintf("⚠ Error: Could not request PTY: %v", err))
				editMsg.ParseMode = api.ModeMarkdown
				bot.Request(editMsg)
				return
			}
		}

		stdoutPipe, _ := session.StdoutPipe()
		stderrPipe, _ := session.StderrPipe()
		multiReader := io.MultiReader(stdoutPipe, stderrPipe)
		session.Start(command)

		done := make(chan error)
		go func() {
			done <- session.Wait()
		}()

		// Race the command completion against a short timeout.
		// This allows us to handle short commands instantly without entering a slow streaming mode.
		shortTimeout := time.After(400 * time.Millisecond)

		// A buffer to accumulate the command's output.
		var outputBuffer bytes.Buffer
		go io.Copy(&outputBuffer, multiReader)
		

		// Race the command completion against a short timeout.
		// If the command finishes before the timeout, we treat it as a "quick command"
		// and send the full output at once.
		// If the timeout wins, we switch to "streaming mode" for a long-running command.
		select {
		case err := <-done:			//Command finished quickly 
			log.Printf("[INFO] Command finished quickly.")
			cleanedOutput := ansiRegex.ReplaceAllString(outputBuffer.String(), "")

			finalHeader := "`" + ssh.SSH_HOST + "`\n"
			var finalStatus string
			if err != nil {
				finalStatus = "⚠ "
			} else {
				finalStatus = "✅ "
			}
			fullHeader := finalStatus + finalHeader
			sendOrEditFinalMessage(bot, chatID, messageID, fullHeader, cleanedOutput)

			if err != nil {
				log.Printf("[ERROR] Simple execution failed: %v. Output: %s", err, outputBuffer.String())
			}
			return

		case <-shortTimeout:		//Command is long-running, switch to streaming mode
			log.Printf("[INFO] Command is long-running. Mode: Refresh=%v", isRefreshMode)

			activeSessionsMutex.Lock()
			activeSessions[messageID] = session
			activeSessionsMutex.Unlock()
			defer func() {
				activeSessionsMutex.Lock()
				delete(activeSessions, messageID)
				activeSessionsMutex.Unlock()
			}()

			pagedMessagesMutex.Lock()
			header := fmt.Sprintf("▶️ Streaming on `%s`:", ssh.SSH_HOST)
			pagedMessages[messageID] = PagedMessage{
				Pages: []string{},
				Header:   header,
				CurrentPage:   0,
				Follow:   false,	// Does not start in auto-scroll mode by default.
			}
			pagedMessagesMutex.Unlock()

			ticker := time.NewTicker(1000 * time.Millisecond)
			defer ticker.Stop()

			var lastText string

			for {
				select {
				case err := <-done:			////Command finished quickly, send final output
					var finalOutput string
					fullBufferStr := outputBuffer.String()

					if isRefreshMode && len(fullBufferStr) > 0 {
						// For refresh mode, the final output is just the last screen state.
						// This prevents saving the entire command history (e.g., every frame of 'top').
						clearScreenCode := "\x1b[2J"
						cursorHomeCode := "\x1b[H"
						lastClear := strings.LastIndex(fullBufferStr, clearScreenCode)
						lastHome := strings.LastIndex(fullBufferStr, cursorHomeCode)
						splitIndex := max(lastClear, lastHome)
						var lastFrame string
						if splitIndex != -1 {
							lastFrame = fullBufferStr[splitIndex:]
						} else {
							lastFrame = fullBufferStr // Fallback if no clear codes are found.
						}
						finalOutput = ansiRegex.ReplaceAllString(lastFrame, "")
					} else {
						// For normal streaming commands (like ping), the final output is the entire history.
						finalOutput = ansiRegex.ReplaceAllString(fullBufferStr, "")
					}

					finalHeader := "`" + ssh.SSH_HOST + "`\n"
					var finalStatus string
					if err != nil {
						finalStatus = "⚠ "
					} else {
						finalStatus = "✅ "
					}
					fullHeader := finalStatus + finalHeader
					sendOrEditFinalMessage(bot, chatID, messageID, fullHeader, finalOutput)

					if err != nil {
						log.Printf("[ERROR] Streaming execution finished with error: %v", err)
					}
					return

				case <-ticker.C:		//Command is long-running, switch to streaming mode

					if outputBuffer.Len() > maxOutputBufferSize {
						outputBuffer.Next(outputBuffer.Len() - maxOutputBufferSize)
					}

					pagedMessagesMutex.Lock()
					state, ok := pagedMessages[messageID]
					if !ok {
						pagedMessagesMutex.Unlock()
						continue
					}

					fullBufferStr := outputBuffer.String()
					var currentScreenContent string

					if isRefreshMode {
						clearScreenCode := "\x1b[2J"
						cursorHomeCode := "\x1b[H"
						lastClear := strings.LastIndex(fullBufferStr, clearScreenCode)
						lastHome := strings.LastIndex(fullBufferStr, cursorHomeCode)
						splitIndex := max(lastClear, lastHome)
						if splitIndex != -1 {
							currentScreenContent = fullBufferStr[splitIndex:]
						} else {
							currentScreenContent = fullBufferStr
						}
					} else {
						currentScreenContent = fullBufferStr
					}

					cleanedOutput := ansiRegex.ReplaceAllString(currentScreenContent, "")
                    
                    pages := buildPages(cleanedOutput, pageLen)
                    
                    currentPageIndex := state.CurrentPage
                    if state.Follow {
                        currentPageIndex = len(pages) - 1 // If follow mode, always show the last one
                    }
					if currentPageIndex < 0 {
                        currentPageIndex = 0
                    }
                    if currentPageIndex >= len(pages) {
                        currentPageIndex = len(pages) - 1
                    }

                    state.Pages = pages
                    state.CurrentPage = currentPageIndex
                    pagedMessages[messageID] = state

                    pageContent := pages[currentPageIndex]
                    newText := state.Header + "\n```sh\n" + pageContent + "```"
                    
                    pagedMessagesMutex.Unlock() 

                    if newText == lastText {
                        continue
                    }
                    lastText = newText

                    stopButton := api.NewInlineKeyboardButtonData("⏹️ Stop", fmt.Sprintf("stop_cmd_%d", messageID))

                    var followButton api.InlineKeyboardButton
                    if state.Follow {
                        followButton = api.NewInlineKeyboardButtonData("📜 Unfollow", fmt.Sprintf("follow_off_%d", messageID))
                    } else {
                        followButton = api.NewInlineKeyboardButtonData("📜 Follow", fmt.Sprintf("follow_on_%d", messageID))
                    }

                    totalPages := len(state.Pages)
                    currentPage := state.CurrentPage

                    paginationKeyboard := getPaginationKeyboard(messageID, currentPage, totalPages)
                    combinedKeyboard := api.NewInlineKeyboardMarkup(
                        paginationKeyboard.InlineKeyboard[0],
                        api.NewInlineKeyboardRow(stopButton, followButton),
                    )
					editMsg := api.NewEditMessageText(chatID, messageID, newText)
					editMsg.ParseMode = api.ModeMarkdown
					editMsg.ReplyMarkup = &combinedKeyboard
					if _, err := bot.Request(editMsg); err != nil {
						log.Printf("[ERROR] Failed to edit message during streaming (ID: %d): %v", messageID, err)

						errStr := err.Error()

						if strings.Contains(errStr, "message to edit not found") || strings.Contains(errStr, "message can't be edited") {
							log.Printf("[INFO] Stopping stream for message %d as it can no longer be edited.", messageID)
							activeSessionsMutex.Lock()
							if session, ok := activeSessions[messageID]; ok {
								session.Signal(sshClient.SIGKILL)
							}
							activeSessionsMutex.Unlock()
							return
						}

						if strings.Contains(errStr, "Too Many Requests") {
							re := regexp.MustCompile(`retry after (\d+)`)
							matches := re.FindStringSubmatch(errStr)

							if len(matches) > 1 {
								retryAfter, _ := strconv.Atoi(matches[1])
								
								log.Printf("[WARN] Rate limit hit for message %d. Pausing for %d seconds.", messageID, retryAfter)

								pagedMessagesMutex.Lock()
								if state, ok := pagedMessages[messageID]; ok {
									if !strings.HasPrefix(state.Header, "⏳") {
										state.Header = "⏳ " + state.Header
										pagedMessages[messageID] = state
										throttledEdit := api.NewEditMessageText(chatID, messageID, state.Header+"\n```sh\n"+lastText+"```")
										throttledEdit.ParseMode = api.ModeMarkdown
										bot.Request(throttledEdit)
									}
								}
								pagedMessagesMutex.Unlock()

								time.Sleep(time.Duration(retryAfter) * time.Second)

								pagedMessagesMutex.Lock()
								if state, ok := pagedMessages[messageID]; ok {
									state.Header = strings.TrimPrefix(state.Header, "⏳ ")
									pagedMessages[messageID] = state
								}
								pagedMessagesMutex.Unlock()

								continue
							}
						}
					}
				}
			}
		}
	} else {
		var SHELL string
		if runtime.GOOS == "windows" {
			SHELL = env.WIN_SHELL
		} else {
			SHELL = env.LINUX_SHELL
		}
		output, err := exec.Command(SHELL, "-c", messageText).CombinedOutput()

		const maxLen = 200
		var outputStr string
		if len(output) > maxLen {
			outputStr = "... (output truncated)\n" + string(output[len(output)-maxLen:])
		} else {
			outputStr = string(output)
		}

		header := "`localhost`\n"
		var finalMessage string
		if err != nil {
			finalMessage = "⚠ " + header
		} else {
			finalMessage = "✅ " + header
		}
		msg := api.NewMessage(chatID, finalMessage+"```sh\n"+outputStr+"```")
		msg.ParseMode = api.ModeMarkdown
		bot.Send(msg)

		if err != nil {
			log.Printf("[ERROR] Local execution error: %v. Output: %s", err, string(output))
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

	// Loading hosts from the hosts.json file
	sshHostsMutex.Lock()
	file, err := os.ReadFile(hostsFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[WARN] hosts.json not found, creating an empty one.")
			_ = os.WriteFile(hostsFilePath, []byte("{}"), 0644)
		} else {
			log.Fatalf("❌ FATAL: Failed to read hosts file: %v", err)
		}
	} else {
		err = json.Unmarshal(file, &sshHosts)
		if err != nil {
			log.Fatalf("❌ FATAL: Failed to parse hosts.json: %v", err)
		}
	}
	sshHostsMutex.Unlock()
	log.Printf("[INFO] Loaded %d hosts from %s", len(sshHosts), hostsFilePath)

	env.SshHostsMap = sshHosts
	if env.LOG_MODE == "DEBUG" {
		env.PrintEnv()
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
        {Command: "tty", Description: "Run command in TTY mode"},
	    {Command: "tty_refresh", Description: "Run in TTY with screen refresh (for top, htop)"},
		{Command: "download", Description: "Download file from server. /download [path]"},
	    {Command: "upload", Description: "Upload file. /upload [path]"},
		{Command: "add_host", Description: "Add a new host. /add_host <alias> <user@ip:port>"},
    	{Command: "del_host", Description: "Delete a host. /del_host <alias>"},
    }
    _, err = bot.Request(api.NewSetMyCommands(commands...))
    if err != nil {
        log.Printf("[ERROR] %s", string(err.Error()))
    }

    for update := range updates {
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
                passwordChan <- messageText
                deleteRequest := api.NewDeleteMessage(chatID, update.Message.MessageID)
                bot.Request(deleteRequest)
                confirmMsg := api.NewMessage(chatID, " `Password received, authenticating...`")
                confirmMsg.ParseMode = api.ModeMarkdown
                bot.Send(confirmMsg)
                continue
            }
        
        case update.CallbackQuery != nil:
            chatID = update.CallbackQuery.Message.Chat.ID
            firstName = update.CallbackQuery.From.FirstName
            lastName = update.CallbackQuery.From.LastName
            userName = update.CallbackQuery.From.UserName
            messageText = update.CallbackQuery.Data

			if messageText == "noop" {
				bot.Request(api.NewCallback(update.CallbackQuery.ID, ""))
				continue
			}

			if strings.HasPrefix(messageText, "page_") {
				parts := strings.Split(messageText, "_")
				if len(parts) != 3 { continue }
				action, msgIDStr := parts[1], parts[2]
				msgID, err := strconv.Atoi(msgIDStr)
				if err != nil { continue }

				pagedMessagesMutex.Lock()
				state, ok := pagedMessages[msgID]
				if !ok {
					pagedMessagesMutex.Unlock()
					bot.Request(api.NewCallback(update.CallbackQuery.ID, "The message is out of date"))
					continue
				}

                totalPages := len(state.Pages)
                currentPage := state.CurrentPage


                if action == "up" {
                    state.Follow = false // Disable follow when manually scrolling up
                    if currentPage > 0 {
                        state.CurrentPage--
                    }
                } else { // "down"
                    if currentPage < totalPages-1 {
                        state.CurrentPage++
                    }
                    if state.CurrentPage == totalPages-1 {
                        state.Follow = true
                    }
                }
                
                if state.CurrentPage == currentPage {
                    pagedMessagesMutex.Unlock()
                    bot.Request(api.NewCallback(update.CallbackQuery.ID, ""))
                    continue
                }

                pagedMessages[msgID] = state
                
                newState := state // Copy to unlock the mutex
                pagedMessagesMutex.Unlock()

                pageContent := newState.Pages[newState.CurrentPage]
                newText := newState.Header + "\n```sh\n" + pageContent + "```"

                // Check if the session is active to decide if a Stop button is needed
                activeSessionsMutex.Lock()
                _, sessionActive := activeSessions[msgID]
                activeSessionsMutex.Unlock()
                
                var keyboard api.InlineKeyboardMarkup
                paginationKeyboard := getPaginationKeyboard(msgID, newState.CurrentPage, len(newState.Pages))
                if sessionActive {
                    stopButton := api.NewInlineKeyboardButtonData("⏹️ Stop", fmt.Sprintf("stop_cmd_%d", msgID))
                    keyboard = api.NewInlineKeyboardMarkup(
                        paginationKeyboard.InlineKeyboard[0],
                        api.NewInlineKeyboardRow(stopButton),
                    )
                } else {
                    keyboard = *paginationKeyboard
                }

				editMsg := api.NewEditMessageText(chatID, msgID, newText)
				editMsg.ParseMode = api.ModeMarkdown
				editMsg.ReplyMarkup = &keyboard
				bot.Request(editMsg)
				bot.Request(api.NewCallback(update.CallbackQuery.ID, ""))
				continue
			}
			
            if strings.HasPrefix(messageText, "stop_cmd_") {
                msgIDStr := strings.TrimPrefix(messageText, "stop_cmd_")
                msgID, _ := strconv.Atoi(msgIDStr)

                // Respond to Telegram that we have accepted the button press
                bot.Request(api.NewCallback(update.CallbackQuery.ID, "Sending stop signal..."))

                activeSessionsMutex.Lock()
                sessionToStop, ok := activeSessions[msgID]
                activeSessionsMutex.Unlock()

                if ok {
                    log.Printf("[INFO] User requested stop for message %d. Sending SIGINT.", msgID)
                    
                    // Send a graceful signal SIGINT
                    if err := sessionToStop.Signal(sshClient.SIGINT); err != nil {
                        log.Printf("[WARN] Failed to send SIGINT signal: %v", err)
                    } else {
                        editedText := update.CallbackQuery.Message.Text + "\n\n--- Sending stop signal (SIGINT)... ---"
                        editMsg := api.NewEditMessageText(chatID, msgID, editedText)
                        editMsg.ReplyMarkup = &api.InlineKeyboardMarkup{InlineKeyboard: [][]api.InlineKeyboardButton{}}
                        bot.Request(editMsg)
                    }

                    // Сheck if the process is alive after 3 seconds.
                    go func() {
                        time.Sleep(3 * time.Second)

                        activeSessionsMutex.Lock()
                        sessionStillExists, stillOk := activeSessions[msgID]
                        activeSessionsMutex.Unlock()

                        // If the session is still in the map, then SIGINT has not terminated the process
                        if stillOk {
                            log.Printf("[WARN] Process for message %d did not stop. Sending SIGKILL.", msgID)
                            if err := sessionStillExists.Signal(sshClient.SIGKILL); err != nil {
                                log.Printf("[WARN] Failed to send SIGKILL signal: %v", err)
                            } else {
                                editedText := update.CallbackQuery.Message.Text + "\n\n--- Process unresponsive, sent force-kill (SIGKILL)... ---"
                                bot.Request(api.NewEditMessageText(chatID, msgID, editedText))
                            }
                        }
                    }()

                } else {
                    log.Printf("[WARN] Stop requested for message %d, but no active session found.", msgID)
                    // If there is no session, the command may have already completed. Remove the button.
                    editMsg := api.NewEditMessageText(chatID, msgID, update.CallbackQuery.Message.Text)
                    editMsg.ReplyMarkup = &api.InlineKeyboardMarkup{InlineKeyboard: [][]api.InlineKeyboardButton{}}
                    bot.Request(editMsg)
                }
                continue
            }

            if strings.HasPrefix(messageText, "follow_") {
                parts := strings.Split(messageText, "_")
                if len(parts) != 3 { continue }
                action, msgIDStr := parts[1], parts[2]
                msgID, err := strconv.Atoi(msgIDStr)
                if err != nil { continue }

                pagedMessagesMutex.Lock()
                state, ok := pagedMessages[msgID]
                if ok {
                    state.Follow = (action == "on") // "on" -> true, "off" -> false
                    pagedMessages[msgID] = state
                }
                pagedMessagesMutex.Unlock()

                bot.Request(api.NewCallback(update.CallbackQuery.ID, fmt.Sprintf("Follow mode: %s", action)))
                // We don't redraw the message here, it will update itself with the next ticker iteration
                continue
            }

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

            _, err = bot.Request(api.NewCallback(update.CallbackQuery.ID, ""))
            if err != nil { log.Printf("[ERROR] %s", string(err.Error())) }
        default:
            continue
        }


        if update.Message != nil && update.Message.Document != nil {
            // If a document has arrived, we pass control to handleFileUpload
            ssh.handleFileUpload(bot, update)
            continue
        }
		
        // Access check
        if chatID != env.TELEGRAM_USER_ID {
            bot.Send(api.NewMessage(chatID, "⛔ Access denied ⛔"))
            log.Printf("[WARN] Unauthorized access from %s %s (%s - %d)", firstName, lastName, userName, chatID)
            continue
        }

        log.Printf("[INFO] Request from %s %s (%s - %d): %s", firstName, lastName, userName, chatID, messageText)

        if strings.HasPrefix(messageText, "/upload") {
            remotePath := strings.TrimSpace(strings.TrimPrefix(messageText, "/upload"))
            if remotePath == "" {
                bot.Send(api.NewMessage(chatID, "To upload a file, specify the path:\n`/upload /path/to/save`\n\nOr just send the file with the path in the signature."))
            } else {
                pendingUploadsMutex.Lock()
                pendingUploads[chatID] = remotePath
                pendingUploadsMutex.Unlock()
                bot.Send(api.NewMessage(chatID, fmt.Sprintf("Path `%s` is set. Now send me the file to upload.", remotePath)))
            }
            continue
        }

        if strings.HasPrefix(messageText, "/download ") {
            remotePath := strings.TrimSpace(strings.TrimPrefix(messageText, "/download"))
            if remotePath == "" {
                bot.Send(api.NewMessage(chatID, "Please specify the path to the file. Example: `/download /etc/hosts`"))
            } else {
                ssh.handleFileDownload(bot, chatID, remotePath)
            }
            continue
        }

		if strings.HasPrefix(messageText, "/add_host") {
			handleAddHost(bot, chatID, messageText)
			continue
		}

		if strings.HasPrefix(messageText, "/del_host") {
			handleDelHost(bot, chatID, messageText)
			continue
		}

        // Disconnect from ssh and clear declared environment (remove temp file)
        if messageText == "/exit" || messageText == "exit" {
            if ssh.SSH_MODE {
                // First, run any cleanup commands using the existing connection
                if env.SSH_SAVE_ENV {
                    // This command is fire-and-forget, so we ignore potential errors
                    ssh.sshRunSimpleCommand("rm /tmp/ssh-bot.temp")
                }

                // Properly close the persistent SSH client connection
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
		if messageText == "/host_list" {
			sshHostsMutex.RLock() 
			
			if len(sshHosts) == 0 {
				sshHostsMutex.RUnlock()
				bot.Send(api.NewMessage(chatID, "No hosts configured. Add one with `/add_host`."))
				continue
			}

			var keyboardButton [][]api.InlineKeyboardButton
			var messageBuilder strings.Builder
			
			messageBuilder.WriteString("Available hosts:\n\n")

			for alias, connStr := range sshHosts {
				messageBuilder.WriteString(fmt.Sprintf("• **%s** -> `%s`\n", alias, connStr))
				
				btn := api.NewInlineKeyboardButtonData(alias, "/ssh "+connStr)
				keyboardButton = append(keyboardButton, []api.InlineKeyboardButton{btn})
			}
			sshHostsMutex.RUnlock()

			keyboard := api.NewInlineKeyboardMarkup(keyboardButton...)
			
			msg := api.NewMessage(chatID, messageBuilder.String())
			msg.ParseMode = api.ModeMarkdown
			msg.ReplyMarkup = &keyboard
			bot.Send(msg)
			continue
		}

        // Switch to selected host via ssh
        if strings.HasPrefix(messageText, "/ssh") {
            // launch the entire connection logic in a separate goroutine
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

                // Connection Successful
                ssh.SSH_MODE = true // Set SSH mode only AFTER a successful connection
                log.Println("[INFO] Connection successful to " + selectedHost)

                // Get system info to display to the user
                output, err := ssh.sshRunSimpleCommand("uname -a")
                if err != nil {
                    log.Printf("[WARN] Failed to run 'uname -a' after connect: %v", err)
                }

                // Update the temporary message with the success status and system info
                msgText := "✅ Connection successful to " + selectedHost + "\n\n" + "```Info\n" + string(output) + "```"
                editMessage := api.NewEditMessageText(chatID, lastMessageID, msgText)
                editMessage.ParseMode = api.ModeMarkdown
                bot.Send(editMessage)

                // Get the initial present working directory (pwd)
                output, err = ssh.sshRunSimpleCommand("pwd")
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
                output, err := ssh.sshRunSimpleCommand(command)
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

        var requestPTY bool
        var isRefreshMode bool
        if strings.HasPrefix(messageText, "/tty_refresh ") {
            isRefreshMode = true
            requestPTY = true // This mode always requires PTY
            messageText = strings.TrimSpace(strings.TrimPrefix(messageText, "/tty_refresh"))
        } else if strings.HasPrefix(messageText, "/tty ") {
            requestPTY = true
            messageText = strings.TrimSpace(strings.TrimPrefix(messageText, "/tty"))
        }
		
        // Run command for execution
        if env.PARALLEL_EXEC {
            go ssh.runCommand(env, bot, chatID, messageText, requestPTY, isRefreshMode)
        } else {
            ssh.runCommand(env, bot, chatID, messageText, requestPTY, isRefreshMode)
        }
    }
}
