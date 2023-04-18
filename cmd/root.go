package cmd

import (
	"crypto/sha256"
	"archive/zip"
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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var apiKey string
var year intvar year int

var rootCmd = &cobra.Command{
	Use:   "vulners_downloader",
	Short: "Download links from Vulners archive with API key parameter",
	Run: func(cmd *cobra.Command, args []string) {
		if apiKey == "" {
			apiKey = viper.GetString("VULNERS_API_KEY")
		}

		if apiKey == "" {
			fmt.Println("Please provide an API key with --api-key or save it in .env file with VULNERS_API_KEY variable.")
			os.Exit(1)
		}

		downloadVulnersLinks(apiKey)
	},
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVarP(&apiKey, "api-key", "a", "", "API key for Vulners archive")
}

func initConfig() {
	viper.SetConfigName(".env")
	viper.SetConfigType("dotenv")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func downloadVulnersLinks(apiKey string) {
	links := []string{
		"cnvd",
		"dsquare",
		"exploitdb",
		"exploitpack",
		"metasploit",
		"packetstorm",
		"saint",
		"seebug",
		"srcincite",
		"vulnerlab",
		"wpexploit",
		"zdt",
		"zeroscience",
	}

	baseURL := "https://vulners.com/api/v3/archive/collection/?type="

	client := &http.Client{}

	if _, err := os.Stat("vulners"); os.IsNotExist(err) {
		os.Mkdir("vulners", 0755)
	}

	for _, link := range links {
		url := baseURL + link
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			log.Printf("Error creating request for %s: %v", link, err)
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")
		req.Header.Set("X-API-KEY", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error downloading %s: %v", link, err)
			continue
	
		if resp.StatusCode != http.StatusOK {
			log.Printf("Error downloading %s. Status code: %d", link, resp.StatusCode)
			continue
		}

		filename := fmt.Sprintf("%s_%s.json", link, time.Now().Format("20060102_150405"))
		filepath := filepath.Join("vulners", filename)

		if _, err := os.Stat(filepath); !os.IsNotExist(err) {
			fileData, _ := ioutil.ReadFile(filepath)
			hash := sha256.Sum256(fileData)
			currentHash := hex.EncodeToString(hash[:])
			responseHash := resp.Header.Get("X-SHA256")

			if currentHash == responseHash {
				log.Printf("%s has already been downloaded", filename)
				continue
			}
		}

		file, err := os.Create(filepath)
		if err != nil {
			log.Printf("Error creating file %s: %v", filepath, err)
			continue
		}

		fileSize, err := io.Copy(file, resp.Body)
		file.Close()

		if fileSize == 131 {
			os.Remove(filepath)
			log.Printf("Downloaded %s is incorrect and has been removed", filename)
		} else {
			log.Printf("Downloaded %s successfully", filename)
		}
	}
}

