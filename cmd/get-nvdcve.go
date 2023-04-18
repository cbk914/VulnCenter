package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var year int

var rootCmd = &cobra.Command{
	Use:   "get-nvdcve",
	Short: "Download NVD CVE data feeds",
	Run: func(cmd *cobra.Command, args []string) {
		downloadNVDCVE(year)
	},
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	rootCmd.PersistentFlags().IntVarP(&year, "year", "y", 0, "Download data for specific year (yyyy)")
}

func downloadNVDCVE(year int) {
	resp, err := http.Get("https://nvd.nist.gov/vuln/data-feeds#JSON_FEED")
	if err != nil {
		log.Fatalf("An error occurred while connecting to the server: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Error fetching NVD data feeds: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	re := regexp.MustCompile(`nvdcve-1.1-[0-9]*\.json\.zip`)
	filenames := re.FindAllString(string(body), -1)

	if _, err := os.Stat("nvd"); os.IsNotExist(err) {
		os.Mkdir("nvd", 0755)
	}

	for _, filename := range filenames {
		if year != 0 && !strings.Contains(filename, strconv.Itoa(year)) {
			continue
		}

		url := "https://static.nvd.nist.gov/feeds/json/cve/1.1/" + filename
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("Error downloading %s: %v", filename, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("Error downloading %s. Status code: %d", filename, resp.StatusCode)
			continue
		}

		filepath := filepath.Join("nvd", filename)
		if _, err := os.Stat(filepath); !os.IsNotExist(err) {
			fileData, _ := ioutil.ReadFile(filepath)
			hash := sha256.Sum256(fileData)
			currentHash := hex.EncodeToString(hash[:])
			responseHash := resp.Header.Get("X-Content-SHA256")
			if currentHash == responseHash {
				continue
			}
		}

		file, err := os.Create(filepath)
		if err != nil {
			log.Printf("Error creating file %s: %v", filepath, err)
			continue
		}

		_, err = io.Copy(file, resp.Body)
		file.Close()
		resp.Body.Close()

		if err != nil {
			log.Printf("Error writing to file %s: %v", filepath, err)
		}

		zipReader, err := zip.OpenReader(filepath)
		if err != nil {
			log.Printf("Error opening zip file %s: %v", filepath, err)
			continue
		}

		for _, f := range zipReader.File {
			dest := filepath.Join("nvd", f.Name)
			outFile, err := os.Create(dest)
			if err != nil {
				log.Printf("Error creating file %s: %v", dest, err)
				continue
			}

			rc, err := f.Open()
			if err != nil {
				log.Printf("Error opening file in zip archive %s: %v", f.Name, err)
				outFile.Close()
				continue
			}

			_, err = io.Copy(outFile, rc)
			rc.Close()
			outFile.Close()

			if err != nil {
				log.Printf("Error writing to file %s: %v", dest, err)
				continue
			}
		}
		zipReader.Close()
	}

	printSummary()
}

func printSummary() {
	fmt.Println(strings.Repeat("-", 120))
	fmt.Println("Summary:".rjust(70))
	fmt.Println(strings.Repeat("-", 120))
	fmt.Printf("%-30s %20s %50s\n", "Filename", "Size", "sha256")
	fmt.Println(strings.Repeat("-", 120))

	files, err := ioutil.ReadDir("nvd")
	if err != nil {
		log.Printf("Error reading directory: %v", err)
		return
	}

	for _, f := range files {
		filePath := filepath.Join("nvd", f.Name())

		fileData, err := ioutil.ReadFile(filePath)
		if err != nil {
			log.Printf("Error reading file %s: %v", filePath, err)
			continue
		}

		hash := sha256.Sum256(fileData)
		hashString := hex.EncodeToString(hash[:])

		fmt.Printf("%-30s %20d %50s\n", f.Name(), f.Size(), hashString)
	}
	fmt.Println(strings.Repeat("-", 120))
}

