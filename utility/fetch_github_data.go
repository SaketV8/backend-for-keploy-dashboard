package utility

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func FetchGitHubData(githubRepo string, endpoint string, c *gin.Context) {
	url := "https://api.github.com/repos/" + githubRepo + endpoint
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Request creation failed"})
		return
	}
	req.Header.Set("User-Agent", "Go-Gin-Client") // GitHub API requires User-Agent

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch data"})
		return
	}
	defer resp.Body.Close()

	// Stream the response directly to the client
	c.DataFromReader(resp.StatusCode, resp.ContentLength, resp.Header.Get("Content-Type"), resp.Body, nil)
}
