package main

import (
    "crypto/sha512"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "strings"

    "github.com/howeyc/gopass"
    "github.com/fatih/color"
)

const (
    dbPath = "~/.getsploit"
    maxAttempts = 3
)

type VulnersClient struct {
    APIKey string
}

type RedisClient struct {
    VulnersClient
}

func (c *RedisClient) Search(query string, fields []string, limit int, offset int) (map[string]interface{}, error) {
    response, err := c._get(fmt.Sprintf("/api/v3/search/lucene/?query=%s&fields=%s&size=%d&sort=order:desc", query, strings.Join(fields, ","), limit), nil)
    if err != nil {
        return nil, err
    }
    var data map[string]interface{}
    if err := json.Unmarshal(response, &data); err != nil {
        return nil, err
    }
    return data, nil
}

func (c *RedisClient) _get(endpoint string, params map[string]string) ([]byte, error) {
    req, err := c.newRequest("GET", endpoint, nil)
    if err != nil {
        return nil, err
    }
    return c.do(req)
}

func (c *RedisClient) newRequest(method, endpoint string, data map[string]string) (*http.Request, error) {
    url := c.vulnersURL(endpoint)
    req, err := http.NewRequest(method, url, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("User-Agent", "getsploit")
    req.Header.Set("X-Vulners-API-Key", c.APIKey)
    return req, nil
}

func (c *RedisClient) do(req *http.Request) ([]byte, error) {
    resp, err := c.HTTPClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    content, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    return content, nil
}

func (c *RedisClient) vulnersURL(endpoint string) string {
    return fmt.Sprintf("https://vulners.com%s", endpoint)
}

func (c *RedisClient) authenticate() error {
    // Check if there's an API key
    apiKeyFile := filepath.Join(dbPath, "apikey.txt")
    apiKeyHash := ""
    if _, err := os.Stat(apiKeyFile); err == nil {
        content, err := ioutil.ReadFile(apiKeyFile)
        if err != nil {
            return err
        }
        apiKeyHash = strings.TrimSpace(string(content))
    }
    for i := 0; i < maxAttempts; i++ {
        fmt.Print("Enter Vulners API key: ")
        apiKey, err := gopass.GetPasswd()
        if err != nil {
            return err
        }
        inputHash := fmt.Sprintf("%x", sha512.Sum512(apiKey))
        if apiKeyHash == inputHash {
            break
        } else {
            color.Red("Invalid API key")
        }
    }
    c.APIKey = string(apiKey)
    return nil
}

func main() {
    // Parse command line arguments
    if len(os.Args) == 1 {
        fmt.Println("No search query provided. Type software name and version to find exploit.")
        os.Exit(1)
    }
    query := os.Args[1]
    fields := []string{"description", "sourceData"}
    limit := 10
    titleOnly := false
    mirrorFiles := false
    localSearch := false
    updateDB := false
    for _, arg := range os.Args[2:] {
        switch arg {
        case "-t", "--title":
            fields = []string{"title"}
            titleOnly = true
        case "-j", "--json":
            // not implemented
            fmt.Println("JSON output not yet implemented")
            os.Exit(1)
        case "-m", "--mirror":
            mirrorFiles = true
        case "-c", "--count":
            if len(os.Args) < 4 {
                fmt.Println("Error: no count provided")
                os.Exit(1)
            }
            var err error
            limit, err = strconv.Atoi(os.Args[3])
            if err != nil {
                fmt.Println("Error: invalid count")
                os.Exit(1)
            }
        case "-l", "--local":
            localSearch = true
        case "-u", "--update":
            updateDB = true
        }
    }

    // Check if search query is provided
    if query == "" {
        fmt.Println("No search query provided. Type software name and version to find exploit.")
        os.Exit(1)
    }

    // Initialize Vulners client
    client := &RedisClient{VulnersClient{}}
    if err := client.authenticate(); err != nil {
        fmt.Printf("Error: %v\n", err)
        os.Exit(1)
    }

    // Perform search
    var searchResults []interface{}
    if localSearch {
        dataDocs, err := client.SearchLocal(query, []string{"title"}, limit, 0, fields)
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            os.Exit(1)
        }
        for _, doc := range dataDocs {
            searchResults = append(searchResults, doc)
        }
    } else {
        data, err := client.Search(query, fields, limit, 0)
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            os.Exit(1)
        }
        searchResults = data["data"].([]interface{})
    }

    // Display results
    table := tablewriter.NewWriter(os.Stdout)
    table.SetHeader([]string{"ID", "Exploit Title", "URL"})
    for _, result := range searchResults {
        resultMap := result.(map[string]interface{})
        title := resultMap["title"].(string)
        if titleOnly {
            if strings.Contains(strings.ToLower(title), strings.ToLower(query)) {
                table.Append([]string{
                    fmt.Sprintf("%.0f", resultMap["id"].(float64)),
                    title,
                    fmt.Sprintf("https://vulners.com/#!exploitdb/view/%.0f", resultMap["id"].(float64)),
                })
            }
        } else {
            table.Append([]string{
                fmt.Sprintf("%.0f", resultMap["id"].(float64)),
                title,
                fmt.Sprintf("https://vulners.com/#!exploitdb/view/%.0f", resultMap["id"].(float64)),
            })
        }
    }
    table.Render()

    // Mirror files
    if mirrorFiles {
        for _, result := range searchResults {
            resultMap := result.(map[string]interface{})
			if len(resultMap["sourceData"].([]interface{})) > 0 {
                fileName := fmt.Sprintf("%.0f_%s", resultMap["id"].(float64), strings.ReplaceAll(resultMap["title"].(string), " ", "_"))
                filePath := fmt.Sprintf("./%s/%s", query, fileName)
                sourceURL := resultMap["sourceData"].([]interface{})[0].(map[string]interface{})["url"].(string)
                fileData, err := client.downloadFile(sourceURL)
                if err != nil {
                    fmt.Printf("Error downloading file %s: %v\n", sourceURL, err)
                    continue
                }
                err = ioutil.WriteFile(filePath, fileData, 0644)
                if err != nil {
                    fmt.Printf("Error writing file %s: %v\n", filePath, err)
                    continue
                }
                fmt.Printf("Downloaded %s\n", fileName)
            }
        }
    }

    // Update local database
    if updateDB {
        if err := client.updateLocalDB(); err != nil {
            fmt.Printf("Error updating local database: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("Local database updated successfully")
    }
}


