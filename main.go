package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"github.com/saketV8/jwt-auth-golang/config"
	"github.com/saketV8/jwt-auth-golang/initializers"
	"github.com/saketV8/jwt-auth-golang/routes"
	"github.com/saketV8/jwt-auth-golang/sqlite"
	"golang.org/x/oauth2"
)

// OAuth2 configuration
var GithubOAuthConfig *oauth2.Config

func init() {
	initializers.LoadEnvVariable()
	config.InitGithubOauthConfig()
}

func main() {
	fmt.Println("-- Backend for Keploy Dashboard --")
	fmt.Println()
	fmt.Println()

	// SETTING UP DATABASE
	db, err := sql.Open("sqlite3", "./app.db")
	if err != nil {
		log.Fatal("ERORR IN DATABASE!!!")
		log.Fatal(err)
	}
	// Making database querable
	UserAccountsDbModel := &sqlite.UserAccountsDbModel{
		DB: db,
	}

	// Starting the server via Run() method
	// passing UserAccountsDbModel down to router
	// then router --> handler
	router := routes.SetupRouter(UserAccountsDbModel)
	err = router.Run()
	if err != nil {
		log.Fatal("ERORR IN SERVER!!!")
		log.Fatal(err)
	}
}
