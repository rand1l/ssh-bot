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

    "golang.org/x/crypto/bcrypt"

    env "github.com/rand1l/ssh-bot/pkg/env"

    api "github.com/go-telegram-bot-api/telegram-bot-api/v5"
    "github.com/pkg/sftp"
    sshClient "golang.org/x/crypto/ssh"
    "golang.org/x/crypto/ssh/knownhosts"
)

const autoLockInactivityDuration = 15 * time.Minute

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

func isNumeric(s string) bool {
    _, err := strconv.Atoi(s)
    return err == nil
}

// updateEnvFile updates a key-value pair in the .env file.
// Creates the file if it doesn't exist.
func updateEnvFile(envFilePath, key, value string) error {
    input, err := os.ReadFile(envFilePath)
    if err != nil && !os.IsNotExist(err) {
        return err
    }

    lines := strings.Split(string(input), "\n")
    keyExists := false
    newLines := []string{}

    // Filter out empty lines and update the key if it exists
    for _, line := range lines {
        if line != "" {
            if strings.HasPrefix(line, key+"=") {
                newLines = append(newLines, key+"="+value)
                keyExists = true
            } else {
                newLines = append(newLines, line)
            }
        }
    }

    if !keyExists {
        newLines = append(newLines, key+"="+value)
    }

    output := strings.Join(newLines, "\n")
    //  Check if the file ends with a newline, add one if not
    if !strings.HasSuffix(output, "\n") {
        output += "\n"
    }

    return os.WriteFile(envFilePath, []byte(output), 0644)
}


const pageLen = 4000

// SSH holds the state and client for a persistent SSH connection.
type SSH struct {
    Pwd             string
    SSHMode        bool
    SSHHost        string
    SSHUser        string
    SSHPort        string
    SSHPrivateKey []byte
    Client          *sshClient.Client
}

const maxFileSize = 48 * 1024 * 1024 // 48MB


// maxOutputBufferSize defines the maximum size of the command output buffer in bytes (1024 KB).
// This prevents a single command from consuming excessive memory and overwhelming the Telegram API.
const maxOutputBufferSize = 1024 * 1024


type BotServer struct {
    bot *api.BotAPI
    env *env.Env
    ssh *SSH

    pinHash         string
    isAuthenticated bool

    lastActivityTime time.Time
    autoLockMutex    *sync.RWMutex

    pendingHostKeyVerifications map[int64]chan bool
    pendingPasswordRequests     map[int64]chan string

    // maps a message ID to a running SSH session.
    // used to stop long-running commands via a callback button.
    activeSessions              map[int]*sshClient.Session
    activeSessionsMutex *sync.Mutex


    // stores the destination path for a file upload that was initiated
    // by the /upload command. The key is the chat ID.
    // It is protected by a mutex to handle concurrent messages safely.var
    pendingUploads              map[int64]string
    pendingUploadsMutex *sync.Mutex

    pagedMessages               map[int]PagedMessage
    pagedMessagesMutex  *sync.Mutex


    sshHosts                    map[string]string
    sshHostsMutex       *sync.RWMutex
}

func (s *BotServer) autoLockChecker() {

    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        s.autoLockMutex.RLock()
        isAuthenticated := s.isAuthenticated
        lastActivity := s.lastActivityTime
        pinIsSet := s.pinHash != ""
        s.autoLockMutex.RUnlock()

        // Start the auto-lock countdown only if a PIN is set and the user is currently authenticated
        if pinIsSet && isAuthenticated {
            if time.Since(lastActivity) > autoLockInactivityDuration {
                s.autoLockMutex.Lock()
                // We re-check isAuthenticated in case the user locked the bot
                if s.isAuthenticated {
                    s.isAuthenticated = false
                    log.Println("[INFO] Bot has been auto-locked due to inactivity.")

                    msg := api.NewMessage(s.env.TELEGRAM_USER_ID, "🔒 The bot is automatically locked after 15 minutes of inactivity.")
                    s.bot.Send(msg)
                }
                s.autoLockMutex.Unlock()
            }
        }
    }
}

func (s *BotServer) handleAddHost(chatID int64, text string) {
    parts := strings.Fields(text)
    if len(parts) != 3 {
        s.bot.Send(api.NewMessage(chatID, "Usage: `/add_host <alias> <user@host:port>`"))
        return
    }
    alias := parts[1]
    connectionString := parts[2]

    s.sshHostsMutex.Lock()
    defer s.sshHostsMutex.Unlock()

    s.sshHosts[alias] = connectionString

    // Save the updated list to a file
    data, err := json.MarshalIndent(s.sshHosts, "", "  ")
    if err != nil {
        log.Printf("[ERROR] Failed to marshal hosts to JSON: %v", err)
        s.bot.Send(api.NewMessage(chatID, "❌ Error saving host list."))
        return
    }

    err = os.WriteFile(hostsFilePath, data, 0644)
    if err != nil {
        log.Printf("[ERROR] Failed to write to hosts.json: %v", err)
        s.bot.Send(api.NewMessage(chatID, "❌ Error saving host list to file."))
        return
    }

    s.bot.Send(api.NewMessage(chatID, fmt.Sprintf("✅ Host '%s' was added.", alias)))
    log.Printf("[INFO] Host '%s' added.", alias)
}

func (s *BotServer) handleDelHost(chatID int64, text string) {
    parts := strings.Fields(text)
    if len(parts) != 2 {
        s.bot.Send(api.NewMessage(chatID, "Usage: `/del_host <alias>`"))
        return
    }
    alias := parts[1]

    s.sshHostsMutex.Lock()
    defer s.sshHostsMutex.Unlock()

    if _, ok := s.sshHosts[alias]; !ok {
        s.bot.Send(api.NewMessage(chatID, fmt.Sprintf("❌ Host '%s' not found.", alias)))
        return
    }

    delete(s.sshHosts, alias)

    // Save the updated list to a file
    data, err := json.MarshalIndent(s.sshHosts, "", "  ")
    if err != nil {
        log.Printf("[ERROR] Failed to marshal hosts to JSON: %v", err)
        s.bot.Send(api.NewMessage(chatID, "❌ Error saving host list."))
        return
    }

    err = os.WriteFile(hostsFilePath, data, 0644)
    if err != nil {
        log.Printf("[ERROR] Failed to write to hosts.json: %v", err)
        s.bot.Send(api.NewMessage(chatID, "❌ Error saving host list to file."))
        return
    }

    s.bot.Send(api.NewMessage(chatID, fmt.Sprintf("✅ Host '%s' was deleted.", alias)))
    log.Printf("[INFO] Host '%s' deleted.", alias)
}

// Handles downloading a file from the server to Telegram
func (s *BotServer) handleFileDownload(chatID int64, remotePath string) {
    if !s.ssh.SSHMode || s.ssh.Client == nil {
        s.bot.Send(api.NewMessage(chatID, "Error: An active SSH connection is required to download files."))
        return
    }

    // Send a placeholder message
    placeholder, _ := s.bot.Send(api.NewMessage(chatID, fmt.Sprintf("⏳ Downloading `%s`...", remotePath)))

    // Create an SFTP client
    sftpClient, err := sftp.NewClient(s.ssh.Client)
    if err != nil {
        errorMsg := fmt.Sprintf("❌ Error creating SFTP client: %v", err)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        log.Printf("[ERROR] SFTP client creation failed: %v", err)
        return
    }
    defer sftpClient.Close()

    // Check file size before reading
    stat, err := sftpClient.Stat(remotePath)
    if err != nil {
        errorMsg := fmt.Sprintf("❌ Failed to get file info for `%s`: %v", remotePath, err)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        return
    }
    if stat.Size() > maxFileSize {
        errorMsg := fmt.Sprintf("❌ File is too large: %.2f MB. Limit: %.2f MB.", float64(stat.Size())/1024/1024, float64(maxFileSize)/1024/1024)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        return
    }
    if stat.IsDir() {
        errorMsg := fmt.Sprintf("❌ The specified path `%s` is a directory, not a file.", remotePath)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        return
    }

    // Open the remote file
    remoteFile, err := sftpClient.Open(remotePath)
    if err != nil {
        errorMsg := fmt.Sprintf("❌ Failed to open remote file `%s`: %v", remotePath, err)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        log.Printf("[ERROR] Remote file open failed: %v", err)
        return
    }
    defer remoteFile.Close()

    // Read the file content
    fileBytes, err := io.ReadAll(remoteFile)
    if err != nil {
        errorMsg := fmt.Sprintf("❌ Error reading file `%s`: %v", remotePath, err)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
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

    s.bot.Send(msg)
    // Delete the placeholder
    s.bot.Request(api.NewDeleteMessage(chatID, placeholder.MessageID))
    log.Printf("[INFO] File downloaded successfully: %s", remotePath)
}

// Manages the process of receiving a document from Telegram
// and uploading it to the remote server via SFTP. It requires a pending
// upload state to be set by the /upload command first.
func (s *BotServer) handleFileUpload(update api.Update) {
    chatID := update.Message.Chat.ID
    doc := update.Message.Document

    // Check for a pending upload path from the /upload command
    s.pendingUploadsMutex.Lock()
    remotePath, isPending := s.pendingUploads[chatID]
    if isPending {
        // Clear the pending state immediately to prevent re-uploading the next file
        delete(s.pendingUploads, chatID)
    }
    s.pendingUploadsMutex.Unlock()

    // If no upload was initiated with the /upload command, reject the file.
    if !isPending {
        s.bot.Send(api.NewMessage(chatID, "❌ Error: To upload a file, you must first specify the destination path with the command:\n`/upload /path/to/destination`\nand attach the file in a subsequent message."))
        return
    }

    // General checks
    if !s.ssh.SSHMode || s.ssh.Client == nil {
        s.bot.Send(api.NewMessage(chatID, "Error: An active SSH connection is required to upload files."))
        return
    }
    if doc.FileSize > maxFileSize {
        s.bot.Send(api.NewMessage(chatID, fmt.Sprintf("❌ File is too large: %.2f MB. Limit: %.2f MB.", float64(doc.FileSize)/1024/1024, float64(maxFileSize)/1024/1024)))
        return
    }

    placeholder, _ := s.bot.Send(api.NewMessage(chatID, fmt.Sprintf("⏳ Uploading file to server at `%s`...", remotePath)))

    // Get a direct URL for the file
    fileURL, err := s.bot.GetFileDirectURL(doc.FileID)
    if err != nil {
        errorMsg := fmt.Sprintf("❌ Failed to get file link: %v", err)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        log.Printf("[ERROR] Failed to get file URL: %v", err)
        return
    }

    // Download the file from Telegram's servers
    resp, err := http.Get(fileURL)
    if err != nil {
        errorMsg := fmt.Sprintf("❌ Failed to download file from Telegram servers: %v", err)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        log.Printf("[ERROR] Failed to download file from Telegram: %v", err)
        return
    }
    defer resp.Body.Close()

    // Create an SFTP client
    sftpClient, err := sftp.NewClient(s.ssh.Client)
    if err != nil {
        errorMsg := fmt.Sprintf("❌ Error creating SFTP client: %v", err)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        log.Printf("[ERROR] SFTP client creation failed: %v", err)
        return
    }
    defer sftpClient.Close()

    // Create the file on the remote server
    dstFile, err := sftpClient.Create(remotePath)
    if err != nil {
        errorMsg := fmt.Sprintf("❌ Failed to create file on server at `%s`: %v", remotePath, err)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        log.Printf("[ERROR] Failed to create remote file: %v", err)
        return
    }
    defer dstFile.Close()

    // Copy the content to the remote file
    bytesCopied, err := io.Copy(dstFile, resp.Body)
    if err != nil {
        errorMsg := fmt.Sprintf("❌ Error writing data to file `%s`: %v", remotePath, err)
        s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, errorMsg))
        log.Printf("[ERROR] Failed to write to remote file: %v", err)
        return
    }

    successMsg := fmt.Sprintf("✅ File `%s` (%.2f MB) uploaded successfully.", remotePath, float64(bytesCopied)/1024/1024)
    s.bot.Request(api.NewEditMessageText(chatID, placeholder.MessageID, successMsg))
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
func (s *BotServer) localChangeDir(chatID int64, message string) {
    newPath := strings.TrimSpace(message[3:])
    err := os.Chdir(newPath)
    if err != nil {
        msg := api.NewMessage(chatID, "⚠ Error changing directory:\n\n```Go\n"+err.Error()+"```")
        msg.ParseMode = api.ModeMarkdown
        s.bot.Send(msg)
        log.Printf("[ERROR] Error changing directory: %s", err.Error())
        return
    }
    pwd, _ := os.Getwd()
    msg := api.NewMessage(chatID, "Current directory:\n\n`"+pwd+"`")
    msg.ParseMode = api.ModeMarkdown
    s.bot.Send(msg)
    log.Printf("[INFO] Current directory: %s", pwd)
}

// Establishes a persistent SSH connection to a remote host.
// It handles key-based authentication, interactive password prompts, and host key verification.
func (s *BotServer) sshConnect(chatID int64) error {
    // If a client is already connected, close the old connection first.
    if s.ssh.Client != nil {
        s.ssh.Client.Close()
        s.ssh.Client = nil
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
        s.pendingHostKeyVerifications[chatID] = decisionChan

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
        s.bot.Send(msg)

        // Block execution until we get a response from the user
        decision := <-decisionChan
        delete(s.pendingHostKeyVerifications, chatID)

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
        s.pendingPasswordRequests[chatID] = passwordChan

        prompt := fmt.Sprintf("Enter password for `%s@%s`:", user, s.ssh.SSHHost)
        if len(questions) > 0 {
            prompt = fmt.Sprintf("%s\n\n```\n%s\n```", prompt, strings.Join(questions, "\n"))
        }
        msg := api.NewMessage(chatID, prompt)
        msg.ParseMode = api.ModeMarkdown
        s.bot.Send(msg)

        // Block and wait for the user to type the password
        password := <-passwordChan
        delete(s.pendingPasswordRequests, chatID)

        return []string{password}, nil
    }

    signer, err := sshClient.ParsePrivateKey(s.ssh.SSHPrivateKey)
    if err != nil {
        log.Printf("[ERROR] Could not parse private key: %v", err)
        return fmt.Errorf("could not parse private key: %w", err)
    }

    timeoutSeconds, _ := strconv.Atoi(s.env.SSH_CONNECT_TIMEOUT)
    timeoutDuration := time.Duration(timeoutSeconds) * time.Second

    // Assemble the final SSH client configuration.
    config := &sshClient.ClientConfig{
        User:            s.ssh.SSHUser,
        HostKeyCallback: customHostKeyCallback,
        Timeout:         timeoutDuration,
        Auth: []sshClient.AuthMethod{
            sshClient.PublicKeys(signer),           // 1. Try public key authentication first.
            sshClient.KeyboardInteractive(keyboardInteractiveChallenge),    // 2. Try interactive password prompt.
            sshClient.Password(s.env.SSH_PASSWORD), // 3. Try non-interactive password from .env.
        },
    }

    log.Printf("[DEBUG] Dialing tcp to %s:%s...", s.ssh.SSHHost, s.ssh.SSHPort)
    client, err := sshClient.Dial("tcp", fmt.Sprintf("%s:%s", s.ssh.SSHHost, s.ssh.SSHPort), config)
    if err != nil {
        log.Printf("[ERROR] Failed to dial: %v", err)
        return fmt.Errorf("failed to dial: %w", err)
    }
    log.Println("[DEBUG] TCP connection established.")

    s.ssh.Client = client
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

func (s *BotServer) sendOrEditFinalMessage(chatID int64, messageID int, header string, cleanedOutput string) {
    // Clean up any previous pagination state for this message to prevent memory leaks
    s.pagedMessagesMutex.Lock()
    delete(s.pagedMessages, messageID)
    s.pagedMessagesMutex.Unlock()

    pages := buildPages(cleanedOutput, pageLen)


    if len(cleanedOutput) > pageLen {
        // Long output: set up a new pagination state.
        s.pagedMessagesMutex.Lock()
        s.pagedMessages[messageID] = PagedMessage{
            Pages:       pages,
            Header:      header,
            CurrentPage: 0,
            Follow:      false,
        }
        s.pagedMessagesMutex.Unlock()

        firstPageContent := pages[0]

        keyboard := getPaginationKeyboard(messageID, 0, len(pages))

        finalText := header + "```sh\n" + firstPageContent + "```"
        finalEdit := api.NewEditMessageText(chatID, messageID, finalText)
        finalEdit.ParseMode = api.ModeMarkdown
        finalEdit.ReplyMarkup = keyboard
        s.bot.Request(finalEdit)

    } else {
        // Short output. Send as is and remove any previous buttons (like "Stop").
        finalText := header
        if len(cleanedOutput) > 0 {
            finalText += "```sh\n" + cleanedOutput + "```"
        }

        finalEdit := api.NewEditMessageText(chatID, messageID, finalText)
        finalEdit.ParseMode = api.ModeMarkdown
        finalEdit.ReplyMarkup = &api.InlineKeyboardMarkup{InlineKeyboard: [][]api.InlineKeyboardButton{}}
        s.bot.Request(finalEdit)
    }
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// runCommand is the core function for executing commands, now acting as a dispatcher.
func (s *BotServer) runCommand(chatID int64, messageText string, requestPTY bool, isRefreshMode bool) {
    if s.ssh.SSHMode {
        s.runSSHCommand(chatID, messageText, requestPTY, isRefreshMode)
    } else {
        s.runLocalCommand(chatID, messageText)
    }
}

// runLocalCommand handles the execution of commands on the local machine where the bot is running.
func (s *BotServer) runLocalCommand(chatID int64, messageText string) {
    var SHELL string
    if runtime.GOOS == "windows" {
        SHELL = s.env.WIN_SHELL
    } else {
        SHELL = s.env.LINUX_SHELL
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
    s.bot.Send(msg)

    if err != nil {
        log.Printf("[ERROR] Local execution error: %v. Output: %s", err, string(output))
    }
}

// runSSHCommand handles the execution of commands over an active SSH connection.
func (s *BotServer) runSSHCommand(chatID int64, messageText string, requestPTY bool, isRefreshMode bool) {
    command := "cd " + s.ssh.Pwd + " && " + messageText

    placeholderText := fmt.Sprintf("▶️ Executing on `%s`...", s.ssh.SSHHost)
    msg, err := s.bot.Send(api.NewMessage(chatID, placeholderText))
    if err != nil {
        log.Printf("[ERROR] Failed to send initial message: %v", err)
        return
    }
    messageID := msg.MessageID

    if s.ssh.Client == nil {
        editMsg := api.NewEditMessageText(chatID, messageID, "⚠ Error: SSH client is not connected.")
        editMsg.ParseMode = api.ModeMarkdown
        s.bot.Request(editMsg)
        return
    }
    session, err := s.ssh.Client.NewSession()
    if err != nil {
        editMsg := api.NewEditMessageText(chatID, messageID, fmt.Sprintf("⚠ Error: Failed to create session: %v", err))
        editMsg.ParseMode = api.ModeMarkdown
        s.bot.Request(editMsg)
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
            s.bot.Request(editMsg)
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

    // For refresh mode, the final output is just the last screen state.
    // This prevents saving the entire command history (e.g., every frame of 'top').
    const clearScreenCode = "\x1b[2J"
    const cursorHomeCode = "\x1b[H"

    // Race the command completion against a short timeout.
    // If the command finishes before the timeout, we treat it as a "quick command"
    // and send the full output at once.
    // If the timeout wins, we switch to "streaming mode" for a long-running command.
    select {
    case err := <-done:
        log.Printf("[INFO] Command finished quickly.")
        cleanedOutput := ansiRegex.ReplaceAllString(outputBuffer.String(), "")

        finalHeader := "`" + s.ssh.SSHHost + "`\n"
        var finalStatus string
        if err != nil {
            finalStatus = "⚠ "
        } else {
            finalStatus = "✅ "
        }
        fullHeader := finalStatus + finalHeader
        s.sendOrEditFinalMessage(chatID, messageID, fullHeader, cleanedOutput)

        if err != nil {
            log.Printf("[ERROR] Simple execution failed: %v. Output: %s", err, outputBuffer.String())
        }
        return

    case <-shortTimeout: // Command is long-running, switch to streaming mode
        log.Printf("[INFO] Command is long-running. Mode: Refresh=%v", isRefreshMode)

        s.activeSessionsMutex.Lock()
        s.activeSessions[messageID] = session
        s.activeSessionsMutex.Unlock()
        defer func() {
            s.activeSessionsMutex.Lock()
            delete(s.activeSessions, messageID)
            s.activeSessionsMutex.Unlock()
        }()

        s.pagedMessagesMutex.Lock()
        header := fmt.Sprintf("▶️ Streaming on `%s`:", s.ssh.SSHHost)
        s.pagedMessages[messageID] = PagedMessage{
            Pages:       []string{},
            Header:      header,
            CurrentPage: 0,
            Follow:      false,         // Does not start in auto-scroll mode by default.
        }
        s.pagedMessagesMutex.Unlock()

        ticker := time.NewTicker(1000 * time.Millisecond)
        defer ticker.Stop()

        var lastText string

        for {
            select {
            case err := <-done: // Command finished, send final output
                var finalOutput string
                fullBufferStr := outputBuffer.String()

                if isRefreshMode && len(fullBufferStr) > 0 {
                    // For refresh mode, the final output is just the last screen state.
                    // This prevents saving the entire command history (e.g., every frame of 'top').
                    lastClear := strings.LastIndex(fullBufferStr, clearScreenCode)
                    lastHome := strings.LastIndex(fullBufferStr, cursorHomeCode)
                    splitIndex := max(lastClear, lastHome)
                    var lastFrame string
                    if splitIndex != -1 {
                        lastFrame = fullBufferStr[splitIndex:]
                    } else {
                        lastFrame = fullBufferStr   // Fallback if no clear codes are found.
                    }
                    finalOutput = ansiRegex.ReplaceAllString(lastFrame, "")
                } else {
                    // For normal streaming commands (like ping), the final output is the entire history.
                    finalOutput = ansiRegex.ReplaceAllString(fullBufferStr, "")
                }

                finalHeader := "`" + s.ssh.SSHHost + "`\n"
                var finalStatus string
                if err != nil {
                    finalStatus = "⚠ "
                } else {
                    finalStatus = "✅ "
                }
                fullHeader := finalStatus + finalHeader
                s.sendOrEditFinalMessage(chatID, messageID, fullHeader, finalOutput)

                if err != nil {
                    log.Printf("[ERROR] Streaming execution finished with error: %v", err)
                }
                return

            case <-ticker.C: // Command is long-running, switch to streaming mode. Ticker for periodic updates.
                if outputBuffer.Len() > maxOutputBufferSize {
                    outputBuffer.Next(outputBuffer.Len() - maxOutputBufferSize)
                }

                s.pagedMessagesMutex.Lock()
                state, ok := s.pagedMessages[messageID]
                if !ok {
                    s.pagedMessagesMutex.Unlock()
                    continue
                }

                fullBufferStr := outputBuffer.String()
                var currentScreenContent string

                if isRefreshMode {
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
                    currentPageIndex = len(pages) - 1       // If follow mode, always show the last one
                }
                if currentPageIndex < 0 {
                    currentPageIndex = 0
                }
                if currentPageIndex >= len(pages) {
                    currentPageIndex = len(pages) - 1
                }

                state.Pages = pages
                state.CurrentPage = currentPageIndex
                s.pagedMessages[messageID] = state

                pageContent := pages[currentPageIndex]
                newText := state.Header + "\n```sh\n" + pageContent + "```"

                s.pagedMessagesMutex.Unlock()

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
                if _, err := s.bot.Request(editMsg); err != nil {
                    log.Printf("[ERROR] Failed to edit message during streaming (ID: %d): %v", messageID, err)

                    errStr := err.Error()

                    if strings.Contains(errStr, "message to edit not found") || strings.Contains(errStr, "message can't be edited") {
                        log.Printf("[INFO] Stopping stream for message %d as it can no longer be edited.", messageID)
                        s.activeSessionsMutex.Lock()
                        if session, ok := s.activeSessions[messageID]; ok {
                            session.Signal(sshClient.SIGKILL)
                        }
                        s.activeSessionsMutex.Unlock()
                        return
                    }

                    if strings.Contains(errStr, "Too Many Requests") {
                        re := regexp.MustCompile(`retry after (\d+)`)
                        matches := re.FindStringSubmatch(errStr)

                        if len(matches) > 1 {
                            retryAfter, _ := strconv.Atoi(matches[1])

                            log.Printf("[WARN] Rate limit hit for message %d. Pausing for %d seconds.", messageID, retryAfter)

                            s.pagedMessagesMutex.Lock()
                            if state, ok := s.pagedMessages[messageID]; ok {
                                if !strings.HasPrefix(state.Header, "⏳") {
                                    state.Header = "⏳ " + state.Header
                                    s.pagedMessages[messageID] = state
                                    throttledEdit := api.NewEditMessageText(chatID, messageID, state.Header+"\n```sh\n"+lastText+"```")
                                    throttledEdit.ParseMode = api.ModeMarkdown
                                    s.bot.Request(throttledEdit)
                                }
                            }
                            s.pagedMessagesMutex.Unlock()

                            time.Sleep(time.Duration(retryAfter) * time.Second)

                            s.pagedMessagesMutex.Lock()
                            if state, ok := s.pagedMessages[messageID]; ok {
                                state.Header = strings.TrimPrefix(state.Header, "⏳ ")
                                s.pagedMessages[messageID] = state
                            }
                            s.pagedMessagesMutex.Unlock()

                            continue
                        }
                    }
                }
            }
        }
    }
}

func (s *BotServer) handleUpdate(update api.Update) {
    switch {
    case update.Message != nil:
        s.handleMessage(update)
    case update.CallbackQuery != nil:
        s.handleCallbackQuery(update.CallbackQuery)
    }
}

func (s *BotServer) handleMessage(update api.Update) {
    chatID := update.Message.Chat.ID

    if chatID != s.env.TELEGRAM_USER_ID {
        s.bot.Send(api.NewMessage(chatID, "⛔ Access denied ⛔"))
        log.Printf("[WARN] Unauthorized access from %s %s (%s - %d)", update.Message.From.FirstName, update.Message.From.LastName, update.Message.From.UserName, chatID)
        return
    }


    s.autoLockMutex.Lock()
    s.lastActivityTime = time.Now()
    s.autoLockMutex.Unlock()


    if s.pinHash != "" && !s.isAuthenticated {
        // Acess /set_pin command even when locked
        if strings.HasPrefix(update.Message.Text, "/set_pin") {
            s.handleSetPinCommand(chatID, update.Message.Text)

            s.bot.Request(api.NewDeleteMessage(chatID, update.Message.MessageID))
            return
        }

        pinAttempt := update.Message.Text

        defer s.bot.Request(api.NewDeleteMessage(chatID, update.Message.MessageID))

        if len(pinAttempt) != 4 || !isNumeric(pinAttempt) {
            msg, _ := s.bot.Send(api.NewMessage(chatID, "🔒 Bot locked. Please enter your 4-digit PIN."))
            // Delete message with hint after several seconds
            go func() {
                time.Sleep(5 * time.Second)
                s.bot.Request(api.NewDeleteMessage(chatID, msg.MessageID))
            }()
            return
        }

        err := bcrypt.CompareHashAndPassword([]byte(s.pinHash), []byte(pinAttempt))
        if err == nil {
            s.isAuthenticated = true
            msg := api.NewMessage(chatID, "✅ Access allowed.")
            s.bot.Send(msg)
        } else {
            msg, _ := s.bot.Send(api.NewMessage(chatID, "❌ Incorrect PIN code."))

            go func() {
                time.Sleep(3 * time.Second)
                s.bot.Request(api.NewDeleteMessage(chatID, msg.MessageID))
            }()
        }
        return // Stop further processing until authenticated
    }

    if passwordChan, ok := s.pendingPasswordRequests[chatID]; ok {
        passwordChan <- update.Message.Text
        s.bot.Request(api.NewDeleteMessage(chatID, update.Message.MessageID))
        confirmMsg := api.NewMessage(chatID, " `Password received, authenticating...`")
        confirmMsg.ParseMode = api.ModeMarkdown
        s.bot.Send(confirmMsg)
        return
    }

    if update.Message.Document != nil {
        s.handleFileUpload(update)
        return
    }

    messageText := update.Message.Text
    log.Printf("[INFO] Request from %d: %s", chatID, messageText)

    switch {
    case strings.HasPrefix(messageText, "/set_pin"):
        s.handleSetPinCommand(chatID, messageText)
        s.bot.Request(api.NewDeleteMessage(chatID, update.Message.MessageID))
    case messageText == "/lock":
        s.handleLockCommand(chatID)
    case strings.HasPrefix(messageText, "/upload"):
        s.handleUploadCommand(chatID, messageText)
    case strings.HasPrefix(messageText, "/download "):
        s.handleDownloadCommand(chatID, messageText)
    case strings.HasPrefix(messageText, "/add_host"):
        s.handleAddHost(chatID, messageText)
    case strings.HasPrefix(messageText, "/del_host"):
        s.handleDelHost(chatID, messageText)
    case messageText == "/exit" || messageText == "exit":
        s.handleExitCommand(chatID)
    case messageText == "/host_list":
        s.handleHostListCommand(chatID)
    case strings.HasPrefix(messageText, "/ssh"):
        // launch the entire connection logic in a separate goroutine
        // to avoid blocking the main loop while waiting for user input (host key/password).
        go s.handleSSHCommand(chatID, messageText)
    case strings.HasPrefix(messageText, "cd "):
        s.handleChangeDirCommand(chatID, messageText)
    default:
        // Run command for execution
        s.handleGenericCommand(chatID, messageText)
    }
}

func (s *BotServer) handleCallbackQuery(callback *api.CallbackQuery) {
    chatID := callback.Message.Chat.ID
    data := callback.Data

    if chatID != s.env.TELEGRAM_USER_ID {
        s.bot.Send(api.NewMessage(chatID, "⛔ Access denied ⛔"))
        return
    }

    s.autoLockMutex.Lock()
    s.lastActivityTime = time.Now()
    s.autoLockMutex.Unlock()


    s.autoLockMutex.RLock()
    isAuthenticated := s.isAuthenticated
    pinIsSet := s.pinHash != ""
    s.autoLockMutex.RUnlock()

    if pinIsSet && !isAuthenticated {
        callbackAlert := api.NewCallback(callback.ID, "🔒 The bot is locked. Please enter your PIN first.")
        s.bot.Request(callbackAlert)
        return
    }

    switch {
    case data == "noop":
        s.bot.Request(api.NewCallback(callback.ID, ""))
    case strings.HasPrefix(data, "page_"):
        s.handlePaginationCallback(callback)
    case strings.HasPrefix(data, "stop_cmd_"):
        s.handleStopCallback(callback)
    case strings.HasPrefix(data, "follow_"):
        s.handleFollowCallback(callback)
    case strings.HasPrefix(data, "verify_host_"):
        s.handleHostVerificationCallback(callback)
    default:
        if strings.HasPrefix(data, "/ssh") {
            go s.handleSSHCommand(chatID, data)
        }
        s.bot.Request(api.NewCallback(callback.ID, ""))
    }
}

func (s *BotServer) handleUploadCommand(chatID int64, text string) {
    remotePath := strings.TrimSpace(strings.TrimPrefix(text, "/upload"))
    if remotePath == "" {
        s.bot.Send(api.NewMessage(chatID, "To upload a file, specify the path:\n`/upload /path/to/save`\n\nOr just send the file with the path in the signature."))
    } else {
        s.pendingUploadsMutex.Lock()
        s.pendingUploads[chatID] = remotePath
        s.pendingUploadsMutex.Unlock()
        s.bot.Send(api.NewMessage(chatID, fmt.Sprintf("Path `%s` is set. Now send me the file to upload.", remotePath)))
    }
}

func (s *BotServer) handleDownloadCommand(chatID int64, text string) {
    remotePath := strings.TrimSpace(strings.TrimPrefix(text, "/download"))
    if remotePath == "" {
        s.bot.Send(api.NewMessage(chatID, "Please specify the path to the file. Example: `/download /etc/hosts`"))
    } else {
        s.handleFileDownload(chatID, remotePath)
    }
}

func (s *BotServer) handleExitCommand(chatID int64) {
    // Disconnect from ssh and clear declared environment (remove temp file)
    if s.ssh.SSHMode {
        if s.env.SSH_SAVE_ENV {
            s.ssh.sshRunSimpleCommand("rm /tmp/ssh-bot.temp")
        }
        if s.ssh.Client != nil {
            s.ssh.Client.Close()
            s.ssh.Client = nil
        }
        s.ssh.SSHMode = false
        messageOutput := api.NewMessage(chatID, "Disconnected from `"+s.ssh.SSHHost+"`")
        messageOutput.ParseMode = api.ModeMarkdown
        s.bot.Send(messageOutput)
        log.Println("[INFO] Disconnected from " + s.ssh.SSHHost)
    } else {
        s.bot.Send(api.NewMessage(chatID, "Remote connection not established"))
        log.Println("[INFO] Remote connection not established")
    }
}

func (s *BotServer) handleHostListCommand(chatID int64) {
    s.sshHostsMutex.RLock()
    defer s.sshHostsMutex.RUnlock()
    if len(s.sshHosts) == 0 {
        s.bot.Send(api.NewMessage(chatID, "No hosts configured. Add one with `/add_host`."))
        return
    }

    var keyboardButton [][]api.InlineKeyboardButton
    var messageBuilder strings.Builder
    messageBuilder.WriteString("Available hosts:\n\n")
    for alias, connStr := range s.sshHosts {
        messageBuilder.WriteString(fmt.Sprintf("• **%s** -> `%s`\n", alias, connStr))
        btn := api.NewInlineKeyboardButtonData(alias, "/ssh "+connStr)
        keyboardButton = append(keyboardButton, []api.InlineKeyboardButton{btn})
    }
    keyboard := api.NewInlineKeyboardMarkup(keyboardButton...)
    msg := api.NewMessage(chatID, messageBuilder.String())
    msg.ParseMode = api.ModeMarkdown
    msg.ReplyMarkup = &keyboard
    s.bot.Send(msg)
}

func (s *BotServer) handleSSHCommand(chatID int64, messageText string) {
    // Switch to selected host via ssh
    selectedHost := strings.TrimSpace(strings.Replace(messageText, "/ssh", "", 1))
    if len(selectedHost) == 0 {
        messageOutput := api.NewMessage(chatID, "Host name not specified\n\nPass the host name as a parameter, for example: `/ssh user@192.168.1.1`")
        messageOutput.ParseMode = api.ModeMarkdown
        s.bot.Send(messageOutput)
        log.Println("[ERROR] Host name not specified")
        return
    }

    // Parse connection parameters first
    s.ssh.SSHHost, s.ssh.SSHUser, s.ssh.SSHPort = s.ssh.paramParse(selectedHost, s.env)

    // Send a temporary "Connecting..." message to the user
    sendMessage, _ := s.bot.Send(api.NewMessage(chatID, "Connecting to "+selectedHost+"..."))
    lastMessageID := sendMessage.MessageID
    log.Println("[INFO] Connection to " + selectedHost)

    // Call our new dedicated connection function
    err := s.sshConnect(chatID)

    // Check for connection errors
    if err != nil {
        s.ssh.SSHMode = false
        detailedError := err.Error()
        msgText := "⚠ Connection error to " + selectedHost + "\n\n" + "```Error\n" + detailedError + "```"
        editMessage := api.NewEditMessageText(chatID, lastMessageID, msgText)
        editMessage.ParseMode = api.ModeMarkdown
        s.bot.Send(editMessage)
        log.Println("[ERROR] Connection error: " + detailedError)
        return
    }

    s.ssh.SSHMode = true
    log.Println("[INFO] Connection successful to " + selectedHost)

    // Get system info to display to the user
    output, err := s.ssh.sshRunSimpleCommand("uname -a")
    if err != nil {
        log.Printf("[WARN] Failed to run 'uname -a' after connect: %v", err)
    }

    // Update the temporary message with the success status and system info
    msgText := "✅ Connection successful to " + selectedHost + "\n\n" + "```Info\n" + string(output) + "```"
    editMessage := api.NewEditMessageText(chatID, lastMessageID, msgText)
    editMessage.ParseMode = api.ModeMarkdown
    s.bot.Send(editMessage)

    // Get the initial present working directory (pwd)
    output, err = s.ssh.sshRunSimpleCommand("pwd")
    if err != nil {
        log.Printf("[WARN] Failed to run 'pwd' after connect: %v", err)
    }
    s.ssh.Pwd = strings.TrimSpace(string(output))
}

func (s *BotServer) handleSetPinCommand(chatID int64, text string) {
    parts := strings.Fields(text)
    if len(parts) != 2 {
        s.bot.Send(api.NewMessage(chatID, "Usage: `/set_pin 1234`"))
        return
    }
    newPin := parts[1]

    if len(newPin) != 4 || !isNumeric(newPin) {
        s.bot.Send(api.NewMessage(chatID, "❌ Error: The PIN code must be exactly 4 digits long."))
        return
    }

    hashedPin, err := bcrypt.GenerateFromPassword([]byte(newPin), bcrypt.DefaultCost)
    if err != nil {
        log.Printf("[ERROR] Failed to hash PIN: %v", err)
        s.bot.Send(api.NewMessage(chatID, "❌ An internal error occurred while setting the PIN."))
        return
    }

    // save hash to .env file
    err = updateEnvFile(".env", "PIN_HASH", string(hashedPin))
    if err != nil {
        log.Printf("[ERROR] Failed to update .env file: %v", err)
        s.bot.Send(api.NewMessage(chatID, "❌ Failed to save new PIN to configuration file."))
        return
    }

    s.pinHash = string(hashedPin)
    s.isAuthenticated = true // Automatically authenticate after setting a new PIN

    s.bot.Send(api.NewMessage(chatID, "✅ The PIN code has been successfully set. You are now authenticated."))
    log.Println("[INFO] PIN has been updated.")
}

func (s *BotServer) handleLockCommand(chatID int64) {
    if s.pinHash == "" {
        s.bot.Send(api.NewMessage(chatID, "ℹ️ PIN is not set. Set it first with `/set_pin 1234`"))
        return
    }
    s.isAuthenticated = false
    s.bot.Send(api.NewMessage(chatID, "🔒 Bot locked"))
    log.Println("[INFO] Bot has been locked by user command.")
}

func (s *BotServer) handleChangeDirCommand(chatID int64, messageText string) {
    // Change directory
    if s.ssh.SSHMode {
        // Get path via ssh
        command := "cd " + s.ssh.Pwd + " && " + messageText + " && pwd"
        output, err := s.ssh.sshRunSimpleCommand(command)
        if err != nil {
            msg := api.NewMessage(chatID, "⚠ Error changing directory:\n\n```ssh\n"+string(output)+"```")
            msg.ParseMode = api.ModeMarkdown
            s.bot.Send(msg)
            log.Printf("[ERROR] Error changing directory: %s", string(output))
            return
        }
        s.ssh.Pwd = strings.TrimSpace(string(output))
        msg := api.NewMessage(chatID, "Current directory:\n\n`"+s.ssh.Pwd+"`")
        msg.ParseMode = api.ModeMarkdown
        s.bot.Send(msg)
        log.Printf("[INFO] Current directory: %s", s.ssh.Pwd)
    } else {
        // Change local directory via os library
        s.localChangeDir(chatID, messageText)
    }
}

func (s *BotServer) handleGenericCommand(chatID int64, messageText string) {
    var requestPTY bool
    var isRefreshMode bool
    if strings.HasPrefix(messageText, "/tty_refresh ") {
        isRefreshMode = true
        requestPTY = true
        messageText = strings.TrimSpace(strings.TrimPrefix(messageText, "/tty_refresh"))
    } else if strings.HasPrefix(messageText, "/tty ") {
        requestPTY = true
        messageText = strings.TrimSpace(strings.TrimPrefix(messageText, "/tty"))
    }

    s.runCommand(chatID, messageText, requestPTY, isRefreshMode)
}

func (s *BotServer) handlePaginationCallback(callback *api.CallbackQuery) {
    parts := strings.Split(callback.Data, "_")
    if len(parts) != 3 {
        return
    }
    action, msgIDStr := parts[1], parts[2]
    msgID, err := strconv.Atoi(msgIDStr)
    if err != nil {
        return
    }

    s.pagedMessagesMutex.Lock()
    state, ok := s.pagedMessages[msgID]
    if !ok {
        s.pagedMessagesMutex.Unlock()
        s.bot.Request(api.NewCallback(callback.ID, "The message is out of date"))
        return
    }

    totalPages := len(state.Pages)
    currentPage := state.CurrentPage

    if action == "up" {
        state.Follow = false
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
        s.pagedMessagesMutex.Unlock()
        s.bot.Request(api.NewCallback(callback.ID, ""))
        return
    }

    s.pagedMessages[msgID] = state
    newState := state
    s.pagedMessagesMutex.Unlock()

    pageContent := newState.Pages[newState.CurrentPage]
    newText := newState.Header + "\n```sh\n" + pageContent + "```"

    s.activeSessionsMutex.Lock()
    _, sessionActive := s.activeSessions[msgID]
    s.activeSessionsMutex.Unlock()

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

    editMsg := api.NewEditMessageText(callback.Message.Chat.ID, msgID, newText)
    editMsg.ParseMode = api.ModeMarkdown
    editMsg.ReplyMarkup = &keyboard
    s.bot.Request(editMsg)
    s.bot.Request(api.NewCallback(callback.ID, ""))
}

func (s *BotServer) handleStopCallback(callback *api.CallbackQuery) {
    msgIDStr := strings.TrimPrefix(callback.Data, "stop_cmd_")
    msgID, _ := strconv.Atoi(msgIDStr)
    s.bot.Request(api.NewCallback(callback.ID, "Sending stop signal..."))

    s.activeSessionsMutex.Lock()
    sessionToStop, ok := s.activeSessions[msgID]
    s.activeSessionsMutex.Unlock()

    if ok {
        log.Printf("[INFO] User requested stop for message %d. Sending SIGINT.", msgID)
        if err := sessionToStop.Signal(sshClient.SIGINT); err != nil {
            log.Printf("[WARN] Failed to send SIGINT signal: %v", err)
        } else {
            editedText := callback.Message.Text + "\n\n--- Sending stop signal (SIGINT)... ---"
            editMsg := api.NewEditMessageText(callback.Message.Chat.ID, msgID, editedText)
            editMsg.ReplyMarkup = &api.InlineKeyboardMarkup{InlineKeyboard: [][]api.InlineKeyboardButton{}}
            s.bot.Request(editMsg)
        }

        go func() {
            time.Sleep(3 * time.Second)
            s.activeSessionsMutex.Lock()
            sessionStillExists, stillOk := s.activeSessions[msgID]
            s.activeSessionsMutex.Unlock()

            if stillOk {
                log.Printf("[WARN] Process for message %d did not stop. Sending SIGKILL.", msgID)
                if err := sessionStillExists.Signal(sshClient.SIGKILL); err != nil {
                    log.Printf("[WARN] Failed to send SIGKILL signal: %v", err)
                } else {
                    editedText := callback.Message.Text + "\n\n--- Process unresponsive, sent force-kill (SIGKILL)... ---"
                    s.bot.Request(api.NewEditMessageText(callback.Message.Chat.ID, msgID, editedText))
                }
            }
        }()
    } else {
        log.Printf("[WARN] Stop requested for message %d, but no active session found.", msgID)
        editMsg := api.NewEditMessageText(callback.Message.Chat.ID, msgID, callback.Message.Text)
        editMsg.ReplyMarkup = &api.InlineKeyboardMarkup{InlineKeyboard: [][]api.InlineKeyboardButton{}}
        s.bot.Request(editMsg)
    }
}

func (s *BotServer) handleFollowCallback(callback *api.CallbackQuery) {
    parts := strings.Split(callback.Data, "_")
    if len(parts) != 3 {
        return
    }
    action, msgIDStr := parts[1], parts[2]
    msgID, err := strconv.Atoi(msgIDStr)
    if err != nil {
        return
    }

    s.pagedMessagesMutex.Lock()
    state, ok := s.pagedMessages[msgID]
    if ok {
        state.Follow = (action == "on")
        s.pagedMessages[msgID] = state
    }
    s.pagedMessagesMutex.Unlock()
    s.bot.Request(api.NewCallback(callback.ID, fmt.Sprintf("Follow mode: %s", action)))
}

func (s *BotServer) handleHostVerificationCallback(callback *api.CallbackQuery) {
    chatID := callback.Message.Chat.ID
    if decisionChan, ok := s.pendingHostKeyVerifications[chatID]; ok {
        var decision bool
        if callback.Data == "verify_host_yes" {
            decision = true
            s.bot.Send(api.NewEditMessageText(chatID, callback.Message.MessageID, "✅ Host key accepted. Continuing connection..."))
        } else {
            decision = false
            s.bot.Send(api.NewEditMessageText(chatID, callback.Message.MessageID, "❌ Host key rejected. Aborting connection."))
        }
        decisionChan <- decision
        s.bot.Request(api.NewCallback(callback.ID, ""))
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

    bot, err := api.NewBotAPI(env.TELEGRAM_BOT_TOKEN)
    if err != nil {
        log.Fatal(err)
    }

    sshState := &SSH{}
    sshState.SSHPrivateKey, _ = os.ReadFile(env.SSH_PRIVATE_KEY_PATH)

    server := &BotServer{
        bot: bot,
        env: env,
        ssh: sshState,

        lastActivityTime: time.Now(),
        autoLockMutex:    &sync.RWMutex{},

        pendingHostKeyVerifications: make(map[int64]chan bool),
        pendingPasswordRequests:     make(map[int64]chan string),
        activeSessions:              make(map[int]*sshClient.Session),
        pendingUploads:              make(map[int64]string),
        pagedMessages:               make(map[int]PagedMessage),
        sshHosts:                    make(map[string]string),

        activeSessionsMutex: &sync.Mutex{},
        pendingUploadsMutex: &sync.Mutex{},
        pagedMessagesMutex:  &sync.Mutex{},
        sshHostsMutex:       &sync.RWMutex{},
    }


    server.pinHash = env.PIN_HASH
    if server.pinHash != "" {
        server.isAuthenticated = false
        log.Println("[INFO] PIN code is set. Bot is locked on startup.")
    } else {
        server.isAuthenticated = true
        log.Println("[INFO] No PIN code set. Bot is unlocked.")
    }

    // Loading hosts from the hosts.json file
    server.sshHostsMutex.Lock()
    file, err := os.ReadFile(hostsFilePath)
    if err != nil {
        if os.IsNotExist(err) {
            log.Printf("[WARN] hosts.json not found, creating an empty one.")
            _ = os.WriteFile(hostsFilePath, []byte("{}"), 0644)
        } else {
            log.Fatalf("❌ FATAL: Failed to read hosts file: %v", err)
        }
    } else {
        err = json.Unmarshal(file, &server.sshHosts)
        if err != nil {
            log.Fatalf("❌ FATAL: Failed to parse hosts.json: %v", err)
        }
    }
    server.sshHostsMutex.Unlock()
    log.Printf("[INFO] Loaded %d hosts from %s", len(server.sshHosts), hostsFilePath)

    env.SshHostsMap = server.sshHosts
    if env.LOG_MODE == "DEBUG" {
        env.PrintEnv()
    }

    go server.autoLockChecker()

    u := api.NewUpdate(0)
    u.Timeout = 30
    updates := server.bot.GetUpdatesChan(u)

    commands := []api.BotCommand{
        {Command: "lock", Description: "Lock the bot (requires PIN to unlock)"},
        {Command: "host_list", Description: "List of hosts for ssh connection"},
        {Command: "exit", Description: "Disconnect from the remote host and clear the declared environment"},
        {Command: "tty", Description: "Run command in TTY mode"},
        {Command: "tty_refresh", Description: "Run in TTY with screen refresh (for top, htop)"},
        {Command: "download", Description: "Download file from server. /download [path]"},
        {Command: "upload", Description: "Upload file. /upload [path]"},
        {Command: "add_host", Description: "Add a new host. /add_host <alias> <user@ip:port>"},
        {Command: "del_host", Description: "Delete a host. /del_host <alias>"},
        {Command: "ssh", Description: "Connect to host. /ssh <user@ip>"},
        {Command: "set_pin", Description: "Set or change the 4-digit PIN code. /set_pin 1234"},
    }
    _, err = server.bot.Request(api.NewSetMyCommands(commands...))
    if err != nil {
        log.Printf("[ERROR] %s", string(err.Error()))
    }

    for update := range updates {
        if server.env.PARALLEL_EXEC {
            go server.handleUpdate(update)
        } else {
            server.handleUpdate(update)
        }
    }
}
