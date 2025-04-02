package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/saketV8/jwt-auth-golang/config"
	"github.com/saketV8/jwt-auth-golang/models"
	"github.com/saketV8/jwt-auth-golang/sqlite"
)

// ============================================================================================= //
// ============================================================================================= //
// ============================================================================================= //
// Github Oauth handlers

// GitHub Login Home Handler
// TODO:
// Integrate in the next app, not the specific page
func GithubLoginHomeHandler(c *gin.Context) {

	//  This for debugging obviously :))
	// fmt.Println("============================= Env Variables =====================")
	// fmt.Println("GITHUB_CLIENT_ID: ", config.GithubOAuthConfig.ClientID)
	// fmt.Println("GITHUB_CLIENT_SECRET: ", config.GithubOAuthConfig.ClientSecret)
	// fmt.Println("GITHUB_REDIRECT_URL: ", config.GithubOAuthConfig.RedirectURL)
	// fmt.Println("Scopes: ", config.GithubOAuthConfig.Scopes)
	// fmt.Println("==================================================================")
	// fmt.Println("==================================================================")
	// fmt.Println("GITHUB_CLIENT_ID:", os.Getenv("GITHUB_CLIENT_ID"))
	// fmt.Println("GITHUB_CLIENT_SECRET:", os.Getenv("GITHUB_CLIENT_SECRET"))
	// fmt.Println("GITHUB_REDIRECT_URL:", os.Getenv("GITHUB_REDIRECT_URL"))
	// fmt.Println("============================= Env Variables =====================")

	html := `<html><body>
	<a href="/api/auth/oauth/github/login">Login with GitHub</a>
	</body></html>`

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

func GithubLoginHandler(ctx *gin.Context) {
	// ctx.JSON(http.StatusOK, gin.H{
	// 	"message": "This is Homepage",
	// })
	url := config.GithubOAuthConfig.AuthCodeURL("random-state")
	ctx.Redirect(http.StatusFound, url)
}

func GithubCallbackHandler(c *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code not found"})
		return
	}

	// Exchange code for access token
	token, err := config.GithubOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}

	// Create OAuth client
	client := config.GithubOAuthConfig.Client(context.Background(), token)

	// Fetch user emails
	emailResp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user emails"})
		return
	}
	defer emailResp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(emailResp.Body).Decode(&emails); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode emails response"})
		return
	}

	// Get one the primary email the emails list :)
	var primaryEmail string
	for _, e := range emails {
		if e.Primary && e.Verified {
			primaryEmail = e.Email
			break
		}
	}
	if primaryEmail == "" && len(emails) > 0 {
		primaryEmail = emails[0].Email
	}

	// Fetch user info from GitHub
	userResp, err := client.Get("https://api.github.com/user")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
		return
	}
	defer userResp.Body.Close()

	var githubUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&githubUser); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode user response"})
		return
	}

	// Map data to UserGitHub model
	// all data are mapped
	// user := models.UserGitHub{
	user := models.UserGitHub{
		GitHubID:          githubUser.ID,
		GitHubUsername:    githubUser.Login,
		Name:              githubUser.Name,
		AvatarURL:         githubUser.AvatarURL,
		Email:             primaryEmail,
		GitHubAccessToken: token.AccessToken,
		// RefreshToken:      refreshTokenString,
	}

	// ==================================================================================== //
	// ==================================================================================== //
	// Save the users details to DB early to get user ID from the table, which
	// we will used as payload in JWT
	// ==================================================================================== //
	// ==================================================================================== //
	// var rowAffected int64

	// rowAffected, err = UserAccDb_Model.InsertOrUpdateGithubUserQuery(user)
	_, err = UserAccDb_Model.InsertOrUpdateGithubUserQuery(user)
	// rowAffected, err = UserAccDb_Model.Insert(body.UserName, body.FirstName, body.LastName, body.PhoneNumber, body.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to insert user account",
			"details": err.Error(),
		})
		return
	}

	// geting id as it will be generated after the first table insertion
	userID, err := UserAccDb_Model.GetUserIDByGitHubID(int(githubUser.ID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get ID of the user",
			"details": err.Error(),
		})
		return
	}

	fmt.Println("🕊️🕊️🕊️🕊️ Value of userID in callback: ", userID, reflect.TypeOf(userID))
	// ==================================================================================== //
	// ==================================================================================== //
	// generating the  || REFRESH TOKEN ||
	// https://golang-jwt.github.io/jwt/usage/create/
	// ==================================================================================== //
	// ==================================================================================== //

	// coverting userID to str before passing as payload
	userIDstr := strconv.Itoa(userID)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// Donot put any personal info here
		"sub": userIDstr,
		// "sub": userID,
		// 1hr * 24 * 30 = 1 month
		// "exp": time.Now().Add(time.Hour * 24 * 30).Unix(),

		// 1hr * 24 = 1 day
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	// Sign and get the complete encoded token as a string using the secret
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("REFRESH_JWT_SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to create JWT Token",
			"details": err.Error(),
		})
		return
	}
	// ==================================================================================== //
	// ==================================================================================== //
	// c.JSON(http.StatusOK, gin.H{
	// 	"message":      "User account successfully created",
	// 	"row-affected": rowAffected,
	// 	"body":         body,
	// })
	// ==================================================================================== //
	// ==================================================================================== //

	// ==================================================================================== //
	// ==================================================================================== //
	// Saving refreshtoken to cookies
	// ==================================================================================== //
	// ==================================================================================== //
	c.SetSameSite(http.SameSiteLaxMode)
	// hover over the SetCookie to get insight :)
	// SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool)
	// 3600 ==> 1 hr
	// 1 * 24 ==> 1 day
	// c.SetCookie("Authorization", refreshTokenString, 3600*24*1000, "", "", false, true)
	c.SetCookie("Authorization", refreshTokenString, 3600*24*1000, "", "localhost", false, true)
	// ==================================================================================== //
	// ==================================================================================== //

	// ==================================================================================== //
	// ==================================================================================== //
	// Redirect to the frontend URL
	// ==================================================================================== //
	// ==================================================================================== //
	frontendURL := "http://localhost:3000/dashboard"
	c.Redirect(http.StatusFound, frontendURL)
	// ==================================================================================== //
	// ==================================================================================== //

	// Respond with mapped user data
	// c.JSON(http.StatusOK, user)
}

func RefreshTokenToAccessTokenGithubOAuth(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	// getting refresh token from cookies
	// Get the Cookie off req
	refreshTokenString, err := ctx.Cookie("Authorization")
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Error in getting cookies from client",
			"details": err.Error(),
		})
		return
	}

	if refreshTokenString == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "No Cookies Found",
		})
		return
	}
	// compare the refreshtoken with saved one in the database
	//look up required user
	// _, err = UserAccDb_Model.RefreshTokenQuery(refreshTokenString)
	// ======================================================================== //
	// user, err := UserAccDb_Model.GetUserRefreshTokenQuery(refreshTokenString)
	// if err != nil {
	// 	ctx.JSON(http.StatusBadRequest, gin.H{
	// 		"error":   "Internal Error Ocurred Refresh Token match",
	// 		"details": err.Error(),
	// 	})
	// 	return
	// }
	// ======================================================================== //

	// we can have error for not having the user found with that refresh token error
	// implement later

	// verify the refresh token JWT to get the claims
	// Parse the JWT token
	token, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token is signed with the expected signing method (HMAC)
		// if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret key used to sign the JWT
		return []byte(os.Getenv("REFRESH_JWT_SECRET")), nil
	})
	if err != nil || !token.Valid {
		// If the token is invalid or parsing fails, respond with an unauthorized error
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":   "Invalid token [Error in Parsing JWT] 🫡",
			"details": err.Error(),
		})
		return
	}

	// Extract claims from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["sub"] == nil {
		// If the token doesn't contain the expected claims, respond with an unauthorized error
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid token claims",
		})
		return
	}

	fmt.Println("🐸🦉🦉 From Refeshtoekn Acess", claims["sub"], reflect.TypeOf(claims["sub"]))

	// generate new accesToken after verifying the refreshToken
	// =================================================== //
	// ACCESS TOKEN
	// https://golang-jwt.github.io/jwt/usage/create/
	// =================================================== //
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// TODO:
		// this user email is from the claims of refresh token, in this case
		// so we have not to look up to database

		// otherwise you can get the user email from db based on refresh token
		// as I am doing here
		// here claims["sub"] is string
		"sub": claims["sub"],
		// "nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		// 5 min
		// "exp": time.Now().Add(time.Second * 60 * 5).Unix(),
		// 30 sec
		// "exp": time.Now().Add(time.Second * 30).Unix(),
		"exp": time.Now().Add(time.Second * 60).Unix(),
	})
	// Sign and get the complete encoded token as a string using the secret
	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("ACCESS_JWT_SECRET")))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to create JWT Token",
			"details": err.Error(),
		})
		return
	}
	fmt.Println("==========================================================================")
	fmt.Println("AcessToken: ", accessTokenString)
	fmt.Println("==========================================================================")
	ctx.JSON(http.StatusOK, gin.H{
		"accessToken": accessTokenString,
	})
}

func GithubUserSessionHandler(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Safe type assertion to avoid panic
	// interface{} --> int
	userIDInt, ok := userID.(int)
	if !ok {
		fmt.Println("🦜🦜 Error Occured")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID type"})
		return
	}

	// Debugging output
	fmt.Println("🐸🐸💅💅 User ID from JWT:", userIDInt, reflect.TypeOf(userIDInt))

	// Fetch user details from database
	user, err := UserAccDb_Model.GetUserByIdQuery(userIDInt)
	if err != nil {
		fmt.Println("🐲🐲 Error in db", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get user account",
			"details": err.Error(),
		})
		return
	}

	ctx.JSON(http.StatusOK, user)
}

// GitHub OAuth callback
// func GithubCallbackHandler(c *gin.Context) {
// 	code := c.Query("code")
// 	if code == "" {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Code not found"})
// 		return
// 	}

// 	// Exchange code for access token
// 	token, err := config.GithubOAuthConfig.Exchange(context.Background(), code)
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
// 		return
// 	}
// 	// Print the token details
// 	fmt.Println("🦉🦉🦉🦉🦉🦉🦉🦉🦉🦉🦉🦉🦉")
// 	fmt.Printf("Access Token: %s\n", token.AccessToken)
// 	fmt.Printf("Token Type: %s\n", token.TokenType)
// 	fmt.Printf("Refresh Token: %s\n", token.RefreshToken)
// 	fmt.Printf("Expiry: %v\n", token.Expiry)

// 	// Fetch user info from GitHub
// 	client := config.GithubOAuthConfig.Client(context.Background(), token)
// 	// resp, err := client.Get("https://api.github.com/user/emails")
// 	resp, err := client.Get("https://api.github.com/user")
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user info"})
// 		return
// 	}
// 	defer resp.Body.Close()

// 	var user map[string]interface{}
// 	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
// 		// var emails []map[string]interface{}
// 		// if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode response"})
// 		return
// 	}

// 	// Respond with user data
// 	c.JSON(http.StatusOK, user)
// 	// fmt.Println("🐦‍🔥🐦‍🔥 Email list")
// 	// fmt.Println(emails)
// 	// c.JSON(http.StatusOK, emails)
// }
