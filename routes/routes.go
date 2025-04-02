package routes

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/saketV8/jwt-auth-golang/config"
	"github.com/saketV8/jwt-auth-golang/handlers"
	"github.com/saketV8/jwt-auth-golang/middleware"
	"github.com/saketV8/jwt-auth-golang/sqlite"
	"github.com/saketV8/jwt-auth-golang/utility"
)

func SetupRouter(UserAccDb_Model *sqlite.UserAccountsDbModel) *gin.Engine {
	rtr := gin.Default()

	// Use CORS middleware
	rtr.Use(config.SetupCORS())

	rtr.GET("/api/", handlers.HomePage)

	rtr.GET("/api/test-api", handlers.TestApi)

	rtr.GET("/api/users", func(ctx *gin.Context) {
		handlers.GetAllUsers(ctx, UserAccDb_Model)
	})

	rtr.GET("/api/user/:user_name", func(ctx *gin.Context) {
		handlers.GetUser(ctx, UserAccDb_Model)
	})

	rtr.POST("/api/create-user-account-test", func(ctx *gin.Context) {
		handlers.CreateUserAccountTest(ctx, UserAccDb_Model)
	})

	rtr.POST("/api/create-user-account", func(ctx *gin.Context) {
		handlers.CreateUserAccount(ctx, UserAccDb_Model)
	})

	rtr.DELETE("/api/delete-user-account", func(ctx *gin.Context) {
		handlers.DeleteUserAccount(ctx, UserAccDb_Model)
	})

	rtr.PUT("/api/update-user-account", func(ctx *gin.Context) {
		handlers.UpdateUserAccount(ctx, UserAccDb_Model)
	})

	// Auth :)

	rtr.POST("/api/auth/signup", func(ctx *gin.Context) {
		handlers.SignUpUserAccount(ctx, UserAccDb_Model)
	})

	rtr.POST("/api/auth/login", func(ctx *gin.Context) {
		handlers.LoginUserAccount(ctx, UserAccDb_Model)
	})

	// rtr.GET("/api/auth/refreshtoken", func(ctx *gin.Context) {
	// 	handlers.RefreshTokenToAccessToken(ctx, UserAccDb_Model)
	// })

	rtr.GET("/api/auth/logout", func(ctx *gin.Context) {
		handlers.LogoutRefreshToken(ctx, UserAccDb_Model)
	})

	rtr.GET("/api/home", middleware.RequireJwtAuthNew(UserAccDb_Model), handlers.HomeHandler)
	// rtr.GET("/api/fetch-session", handlers.SessionHandler)
	// rtr.GET("/api/fetch-session", middleware.RequireJwtAuthNew(UserAccDb_Model), handlers.SessionHandler)
	// rtr.GET("/api/home", middleware.RequireAuth(UserAccDb_Model), handlers.HomeHandler)

	// returning so that we can run the method .Run from main.go

	// Github oauth
	rtr.GET("/api/auth/oauth/github/home", handlers.GithubLoginHomeHandler)
	rtr.GET("/api/auth/oauth/github/login", handlers.GithubLoginHandler)
	// rtr.GET("/api/auth/oauth/github/callback", handlers.GithubCallbackHandler)
	rtr.GET("/api/auth/oauth/github/callback", func(ctx *gin.Context) {
		handlers.GithubCallbackHandler(ctx, UserAccDb_Model)
	})
	rtr.GET("/api/auth/refreshtoken", func(ctx *gin.Context) {
		handlers.RefreshTokenToAccessTokenGithubOAuth(ctx, UserAccDb_Model)
	})
	rtr.GET("/api/fetch-session", middleware.RequireJwtAuthNew(UserAccDb_Model), func(ctx *gin.Context) {
		handlers.GithubUserSessionHandler(ctx, UserAccDb_Model)
	})

	rtr.GET("/api/github/:owner/:repo/issues", func(ctx *gin.Context) {
		ownerParam := ctx.Param("owner")
		repoParam := ctx.Param("repo")
		fmt.Println("=====================================")
		fmt.Println("=====================================")
		fmt.Println(ownerParam + repoParam)
		fmt.Println("=====================================")
		fmt.Println("=====================================")
		utility.FetchGitHubData(ownerParam+"/"+repoParam, "/issues?per_page=100", ctx)
	})

	rtr.GET("/api/github/:owner/:repo/pull-requests", func(ctx *gin.Context) {
		ownerParam := ctx.Param("owner")
		repoParam := ctx.Param("repo")
		utility.FetchGitHubData(ownerParam+"/"+repoParam, "/pulls?per_page=100", ctx)
	})
	return rtr
}
