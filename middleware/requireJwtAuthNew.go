package middleware

import (
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/saketV8/jwt-auth-golang/sqlite"
)

// RequireAuth is a middleware function that validates the user's authentication token.

// It checks the JWT provided in the "Authorization" cookie and verifies the user in the database.
func RequireJwtAuthNew(UserAccDb_Model *sqlite.UserAccountsDbModel) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// ################# USING COOKIES for getting access token 😍 #################
		// Extract the token from the "Authorization" cookie
		// tokenString, err := ctx.Cookie("Authorization")
		// if err != nil {
		// 	// If the cookie is missing or cannot be retrieved, respond with an unauthorized error
		// 	ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		// 		"error":   "Unauthorized: missing token",
		// 		"details": err.Error(),
		// 	})
		// 	return
		// }
		// fmt.Println("🐥 Token String:", tokenString)

		// ################# USING Authorization HEADER for token 😍 #################
		// Extract the token from the "Authorization" header
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			// If the Authorization header is missing, respond with an unauthorized error
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized: missing Authorization header",
			})
			return
		}

		// Check if the header starts with "Bearer "
		if !strings.HasPrefix(authHeader, "Bearer ") {
			// If the token is not prefixed with "Bearer ", respond with an error
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token format: must start with 'Bearer '",
			})
			return
		}

		// Extract the token string by removing the "Bearer " prefix
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		fmt.Println()
		fmt.Println("================================")
		fmt.Println("☑️ Token String:", tokenString)
		fmt.Println("================================")
		fmt.Println()

		// Parse the JWT token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Ensure the token is signed with the expected signing method (HMAC)
			// if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Return the secret key used to sign the JWT
			return []byte(os.Getenv("ACCESS_JWT_SECRET")), nil
		})
		if err != nil || !token.Valid {
			// If the token is invalid or parsing fails, respond with an unauthorized error
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "Invalid token [Error in Parsing & Verifying JWT] 🫡",
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
		// // Get the user's email from the "sub" claim
		// email, ok := claims["sub"].(string)
		// if !ok {
		// 	// Handle the error if the "sub" claim is not a valid string
		// 	fmt.Println("Invalid 'sub' claim: not a string")
		// 	ctx.AbortWithStatus(http.StatusUnauthorized)
		// 	return
		// }

		// _ = email

		// not using the db query
		// advantages of JWT

		// Query the database to find the user by email
		// user, err := UserAccDb_Model.GetUserByEmailQuery(email)
		// if err != nil {
		// 	// If the user is not found, respond with an unauthorized error
		// 	ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		// 		"error": "User not found",
		// 	})
		// 	return
		// }

		// Attach the user information to the request context for further use
		// ctx.Set("user", user)
		fmt.Println("1111111111111111")
		// userIDStr := fmt.Sprintf("%v", claims["sub"])
		userIDstr, ok := claims["sub"]
		if !ok {
			// Handle the error if the "sub" claim is not a valid string
			fmt.Println("Invalid 'sub' claim")
			ctx.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		fmt.Println("22222222222222222222222")
		// coverting str --> int
		userID, err := strconv.Atoi(userIDstr.(string))
		if err != nil {
			fmt.Println("💅💅 Error in string to int")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format in token"})
			return
		}
		fmt.Println("🐸🐸🎀🎀 UserID", userID, reflect.TypeOf(userID))
		ctx.Set("user_id", userID)

		// Proceed to the next handler in the chain
		ctx.Next()
	}
}
