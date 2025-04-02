package models

// ========================================================================== //
// ========================================================================== //
// ========================================================================== //
// Github OAuth :)

type UserGitHub struct {
	ID                int    `json:"id"`
	GitHubID          int64  `json:"github_id"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	AvatarURL         string `json:"avatar_url"`
	GitHubUsername    string `json:"github_username"`
	GitHubAccessToken string `json:"github_access_token"`
	RefreshToken      string `json:"refresh_token"`
}

type UserGitHubWithoutRefresh struct {
	ID                int    `json:"id"`
	GitHubID          int64  `json:"github_id"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	AvatarURL         string `json:"avatar_url"`
	GitHubUsername    string `json:"github_username"`
	GitHubAccessToken string `json:"github_access_token"`
	// RefreshToken      string `json:"refresh_token"`
}

type UserGitHubWithoutRefreshAndAcess struct {
	ID             int    `json:"id"`
	GitHubID       int64  `json:"github_id"`
	Email          string `json:"email"`
	Name           string `json:"name"`
	AvatarURL      string `json:"avatar_url"`
	GitHubUsername string `json:"github_username"`
	// GitHubAccessToken string `json:"github_access_token"`
	// RefreshToken      string `json:"refresh_token"`
}
