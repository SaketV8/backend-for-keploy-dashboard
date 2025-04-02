package models

// struct for database table
type UserAccount struct {
	ID          int
	UserName    string
	FirstName   string
	LastName    string
	PhoneNumber string
	Email       string
}

// body for post, put, delete request
type RequestBody struct {
	UserName    string `json:"user_name"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
	Email       string `json:"email"`
}

type CreateUserRequestBody struct {
	// same as <RequestBody>
	RequestBody
}

type UpdateUserRequestBody struct {
	// same as <RequestBody>
	RequestBody
}

type DeleteRequestBody struct {
	UserName string `json:"user_name" binding:"required"`
}

type TestUserStruct struct {
	UserName    string
	FirstName   string
	LastName    string
	PhoneNumber string
	Email       string
}

type User struct {
	Email    string
	Password string
}
