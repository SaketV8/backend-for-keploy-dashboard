package handlers

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/saketV8/jwt-auth-golang/models"
	"github.com/saketV8/jwt-auth-golang/sqlite"
	"golang.org/x/crypto/bcrypt"
)

func HomePage(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"message": "This is Homepage",
	})
}

func TestApi(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"message": "ok-tested 👍",
	})
}

func GetAllUsers(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	//calling <All> method of <UserAccDb_Model>
	users, err := UserAccDb_Model.All()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get user accounts",
			"details": err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, users)
}

func GetUser(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	// extracting the <user_name> from url
	userNameParam := ctx.Param("user_name")

	//calling <GetByUserName> method of <UserAccDb_Model>
	userAcc, err := UserAccDb_Model.GetByUserName(userNameParam)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to get user account",
			"details": err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, userAcc)
}

func CreateUserAccountTest(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	var rowAffected int64

	// creating data to insert :)
	TestUser := models.TestUserStruct{
		UserName:    "mark",
		FirstName:   "mark",
		LastName:    "manson",
		PhoneNumber: "888-888-909",
		Email:       "markmanson@example.com",
	}

	//calling <Insert> method of <UserAccDb_Model>
	rowAffected, err := UserAccDb_Model.Insert(TestUser.UserName, TestUser.FirstName, TestUser.LastName, TestUser.PhoneNumber, TestUser.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to insert <Test> user account",
			"details": err.Error(),
			"body":    TestUser,
		})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message":      "User account successfully created",
		"row-affected": rowAffected,
		"body":         TestUser,
	})
}

func CreateUserAccount(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	// incoming request data (body of post request)
	var body models.CreateUserRequestBody
	var rowAffected int64

	// Bind the JSON request body to the struct
	// err := ctx.BindJSON(&body)
	err := ctx.Bind(&body)
	if err != nil {
		// If binding fails, return a 400 error with the error message
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid JSON",
			"details": err.Error(),
		})
		return
	}

	rowAffected, err = UserAccDb_Model.Insert(body.UserName, body.FirstName, body.LastName, body.PhoneNumber, body.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to insert user account",
			"details": err.Error(),
			"body":    body,
		})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message":      "User account successfully created",
		"row-affected": rowAffected,
		"body":         body,
	})
}

func UpdateUserAccount(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	// incoming request data (body of post request)
	var body models.UpdateUserRequestBody
	var rowAffected int64

	// Bind the JSON to the <RequestBody> struct
	// err := ctx.BindJSON(&body)
	err := ctx.Bind(&body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid JSON",
			"details": err.Error(),
		})
		return
	}

	// Insert the user data into the database
	rowAffected, err = UserAccDb_Model.Update(body.UserName, body.FirstName, body.LastName, body.PhoneNumber, body.Email)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to update user account",
			"details": err.Error(),
			"body":    body,
		})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message":      "User account successfully updated",
		"row-affected": rowAffected,
		"body":         body,
	})
}

func DeleteUserAccount(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	// incoming request data (body of post request)
	var body models.DeleteRequestBody
	var rowAffected int64

	// Bind the JSON to the <DeleteRequestBody> struct
	// err := ctx.BindJSON(&body)
	err := ctx.Bind(&body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid JSON",
			"details": err.Error(),
		})
		return
	}
	rowAffected, err = UserAccDb_Model.Delete(body.UserName)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to delete user account",
			"details": err.Error(),
			"body":    body,
		})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"message":      "User account successfully delete",
		"row-affected": rowAffected,
		"body":         body,
	})
}

// Tutorial Based on Express JS
// ============================================================================================= //
// ============================================================================================= //
// ============================================================================================= //
// Register Controller (Handler)
func SignUpUserAccount(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	// incoming request data (body of post request)
	// get the email/pass off req body
	var body struct {
		Email    string
		Password string
	}
	err := ctx.Bind(&body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid JSON",
			"details": err.Error(),
		})
		return
	}

	if body.Email == "" || body.Password == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "Null Email or Password",
		})
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Error in Password Hashing",
			"details": err.Error(),
		})
		return
	}

	// Create the user
	user := models.User{
		Email:    body.Email,
		Password: string(hash),
	}

	// storing the user in Database
	rowAffected, err := UserAccDb_Model.SignUpUserQuery(user.Email, user.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to signup user",
			"details": err.Error(),
			"body":    body,
		})
		return
	}

	// Respond
	ctx.JSON(http.StatusOK, gin.H{
		"message":      "User account successfully signed up",
		"row-affected": rowAffected,
		"body":         body,
	})
}

func LoginUserAccount(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
	// extracting the <user_name> from url

	//get the email and pass of the body
	var body struct {
		Email    string
		Password string
	}
	err := ctx.Bind(&body)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid JSON",
			"details": err.Error(),
		})
		return
	}

	//look up required user
	user, err := UserAccDb_Model.LoginUserQuery(body.Email)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Internal Error Ocurred during DB auth",
			"details": err.Error(),
		})
		return
	}
	// you can have user not exist error too :)

	// compare sent in pass with saved user password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Error During matching hashed password, Invalid Email and Password",
			"details": err.Error(),
		})
		return
	}
	// Generate a jwt token and refresh token

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.

	// =================================================== //
	// ACCESS TOKEN
	// https://golang-jwt.github.io/jwt/usage/create/
	// =================================================== //
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// Here I have to actually send User Id, as it can be seen whats been in JWT
		// Donot put any personal info here
		"sub": user.Email,
		// "nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
		// 5 min
		// "exp": time.Now().Add(time.Second * 60 * 5).Unix(),
		// 30 sec
		// "exp": time.Now().Add(time.Second * 30).Unix(),
		"exp": time.Now().Add(time.Second * 60).Unix(),
	})
	// Sign and get the complete encoded token as a string using the secret
	JWT_SEcrt := os.Getenv("ACCESS_JWT_SECRET")
	fmt.Println("🦜🦜 JWT SECRETE: ", JWT_SEcrt)
	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("ACCESS_JWT_SECRET")))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to create JWT Token",
			"details": err.Error(),
		})
		return
	}
	// =================================================== //
	// =================================================== //

	// =================================================== //
	// REFRESH TOKEN
	// https://golang-jwt.github.io/jwt/usage/create/
	// =================================================== //
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		// Donot put any personal info here
		"sub": user.Email,
		// 1hr * 24 * 30 = 1 month
		// "exp": time.Now().Add(time.Hour * 24 * 30).Unix(),

		// 1hr * 24 = 1 day
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})
	// Sign and get the complete encoded token as a string using the secret
	refreshTokenString, err := refreshToken.SignedString([]byte(os.Getenv("REFRESH_JWT_SECRET")))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Failed to create JWT Token",
			"details": err.Error(),
		})
		return
	}
	// =================================================== //
	// =================================================== //

	// after generating the access token and refresh token

	// save the refresh token in Database
	_, err = UserAccDb_Model.RefreshTokenInsertQuery(refreshTokenString, body.Email)
	// rowAffected, err := UserAccDb_Model.RefreshTokenInsertQuery(refreshTokenString)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Failed to saved the user refresh token",
			"details": err.Error(),
		})
		return
	}

	// and send both access and refresh token as response to user
	// =================================================== //
	// cannot send refresh token to user, we have to save it
	// in http only cookies ==> not available to javascript
	// =================================================== //

	// save it to cookies (refresh token)

	// NOTE:
	// By setting SameSite to Lax, you're allowing your frontend application to interact with your backend API
	// from a different URL, while still maintaining some level of security against cross-site request forgery (CSRF) attacks.
	// ctx.SetSameSite(http.SameSiteNoneMode)
	ctx.SetSameSite(http.SameSiteLaxMode)
	// hover over the SetCookie to get insight :)
	// SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool)
	// 3600 ==> 1 hr
	// 1 * 24 ==> 1 day
	ctx.SetCookie("Authorization", refreshTokenString, 3600*24*1000, "", "", false, true)
	// ctx.SetCookie("Authorization", refreshTokenString, 3600*24*1000, "", "", true, true)

	// send it back
	// as we are saving in cookies we can opt out for sending cookies
	ctx.JSON(http.StatusOK, gin.H{
		"accessToken": accessTokenString,
		// instead save it in the cookies
		// "refreshToken": refreshTokenString,
	})
}

func RefreshTokenToAccessToken(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
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
	user, err := UserAccDb_Model.GetUserRefreshTokenQuery(refreshTokenString)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Internal Error Ocurred Refresh Token match",
			"details": err.Error(),
		})
		return
	}

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
		"sub": user.Email,
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

	ctx.JSON(http.StatusOK, gin.H{
		"accessToken": accessTokenString,
	})
}

// client side: delete acess tokenn from front end variable
// backend side: and delete refresh token from db and cookies from browser
func LogoutRefreshToken(ctx *gin.Context, UserAccDb_Model *sqlite.UserAccountsDbModel) {
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
		ctx.JSON(http.StatusOK, gin.H{
			"details": "Cookies deleted successfullly (1)",
		})
		return
	}

	// deleting the refresh token from the database
	_, err = UserAccDb_Model.RefreshTokenDeleteQuery(refreshTokenString)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error":   "Internal Error Ocurred Refresh Token deletion",
			"details": err.Error(),
		})
		return
	}

	// deleting the broswer cookies
	// save it to cookies (refresh token)
	ctx.SetSameSite(http.SameSiteLaxMode)
	// https://stackoverflow.com/a/59736764
	// ctx.SetCookie("Authorization", "", 0, "", "", true, true)
	// secure to false for localhost, maybe
	ctx.SetCookie("Authorization", "", 0, "", "", false, true)

	// TODO:
	// we can clear cookies when refresh token found in db
	// not so important
	ctx.JSON(http.StatusOK, gin.H{
		"details": "Cookies deleted successfullly (2)",
	})
}

func HomeHandler(ctx *gin.Context) {

	// user, ok := ctx.Get("user")
	// if !ok {
	// 	// Handle the case where the user information is not available
	// 	ctx.AbortWithError(http.StatusUnauthorized, errors.New("user information not found"))
	// 	return
	// }

	// Use the retrieved user information
	// log.Println("User:", user)

	ctx.JSON(http.StatusOK, gin.H{
		"message": "This is secured route",
		// "user":    user,
	})
}

func SessionHandler(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"name":  "Dharamvir Bharati",
		"email": "dharamvirbharati@gmail.com",
	})
}
