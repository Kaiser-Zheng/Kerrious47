package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

const (
	saltSize    = 16
	nonceSize   = 12
	keySize     = 32
	timeCost    = 1
	memoryCost  = 64 * 1024
	parallelism = 4
)

func main() {
	encryptFlag := flag.Bool("e", false, "Encrypt files")
	decryptFlag := flag.Bool("d", false, "Decrypt files")
	flag.Parse()

	if *encryptFlag == *decryptFlag {
		fmt.Println("Please specify either -e for encryption or -d for decryption")
		return
	}

	password := getPassword(*encryptFlag)

	if *encryptFlag {
		encryptFiles(password)
	} else {
		decryptFiles(password)
	}
}

func getPassword(isEncrypt bool) []byte {
	var password []byte
	var err error

	fmt.Print("Enter password: ")
	password, err = term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		fmt.Println("Error reading password:", err)
		os.Exit(1)
	}

	if isEncrypt {
		fmt.Print("Confirm password: ")
		confirmPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()

		if err != nil {
			fmt.Println("Error reading password:", err)
			os.Exit(1)
		}

		if string(password) != string(confirmPassword) {
			fmt.Println("Passwords do not match")
			os.Exit(1)
		}
	}

	return password
}

func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, timeCost, memoryCost, parallelism, keySize)
}

func encryptFiles(password []byte) {
	executablePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error getting executable path:", err)
		return
	}
	executableName := filepath.Base(executablePath)

	// Use filepath.WalkDir to traverse directories and subdirectories
	var files []string
	err = filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
			return nil
		}

		if !d.IsDir() && filepath.Base(path) != executableName && !strings.HasSuffix(path, ".enc") {
			files = append(files, path)
		}

		return nil
	})

	if err != nil {
		fmt.Println("Error listing files:", err)
		return
	}

	for _, file := range files {
		// Skip the executable and already encrypted files
		if file == executableName || strings.HasSuffix(file, ".enc") {
			continue
		}

		salt := make([]byte, saltSize)
		if _, err := rand.Read(salt); err != nil {
			fmt.Printf("Error generating salt for %s: %v\n", file, err)
			continue
		}

		key := deriveKey(password, salt)

		aead, err := chacha20poly1305.New(key)
		if err != nil {
			fmt.Printf("Error creating AEAD for %s: %v\n", file, err)
			continue
		}

		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			fmt.Printf("Error generating nonce for %s: %v\n", file, err)
			continue
		}

		plaintext, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("Error reading file %s: %v\n", file, err)
			continue
		}

		ciphertext := aead.Seal(nil, nonce, plaintext, nil)

		encryptedFile, err := os.Create(file + ".enc")
		if err != nil {
			fmt.Printf("Error creating encrypted file for %s: %v\n", file, err)
			continue
		}
		defer encryptedFile.Close()

		if _, err := encryptedFile.Write(salt); err != nil {
			fmt.Printf("Error writing salt to %s.enc: %v\n", file, err)
			continue
		}
		if _, err := encryptedFile.Write(nonce); err != nil {
			fmt.Printf("Error writing nonce to %s.enc: %v\n", file, err)
			continue
		}
		if _, err := encryptedFile.Write(ciphertext); err != nil {
			fmt.Printf("Error writing ciphertext to %s.enc: %v\n", file, err)
			continue
		}

		if err := os.Remove(file); err != nil {
			fmt.Printf("Error deleting original file %s: %v\n", file, err)
			continue
		}

		fmt.Printf("Successfully encrypted %s\n", file)
	}
}

func decryptFiles(password []byte) {
	var files []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Printf("Error accessing path %s: %v\n", path, err)
			return nil
		}

		if !d.IsDir() && strings.HasSuffix(path, ".enc") {
			files = append(files, path)
		}

		return nil
	})

	if err != nil {
		fmt.Println("Error listing encrypted files:", err)
		return
	}

	for _, file := range files {
		encryptedData, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("Error reading encrypted file %s: %v\n", file, err)
			continue
		}

		salt := encryptedData[:saltSize]
		nonce := encryptedData[saltSize : saltSize+nonceSize]
		ciphertext := encryptedData[saltSize+nonceSize:]

		key := deriveKey(password, salt)

		aead, err := chacha20poly1305.New(key)
		if err != nil {
			fmt.Printf("Error creating AEAD for %s: %v\n", file, err)
			continue
		}

		plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			fmt.Printf("Error decrypting %s: %v\n", file, err)
			continue
		}

		decryptedFile := strings.TrimSuffix(file, ".enc")
		if err := os.WriteFile(decryptedFile, plaintext, 0644); err != nil {
			fmt.Printf("Error writing decrypted file %s: %v\n", decryptedFile, err)
			continue
		}

		if err := os.Remove(file); err != nil {
			fmt.Printf("Error deleting encrypted file %s: %v\n", file, err)
			continue
		}

		fmt.Printf("Successfully decrypted %s\n", file)
	}
}
