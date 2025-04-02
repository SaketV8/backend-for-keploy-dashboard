package sqlite

import (
	"database/sql"

	"github.com/saketV8/jwt-auth-golang/models"
)

// for query data using sql in sqlite
type UserAccountsDbModel struct {
	DB *sql.DB
}

// this function is method for UserAccountsModel

// to get data from the table by <user_name>
func (UserAccDb_Model *UserAccountsDbModel) GetByUserName(user_name string) (UserAcc models.UserAccount, err error) {
	statement := `SELECT id, user_name, first_name, last_name, phone_number, email FROM user_accounts WHERE user_name = ?`

	err = UserAccDb_Model.DB.QueryRow(statement, user_name).Scan(&UserAcc.ID, &UserAcc.UserName, &UserAcc.FirstName, &UserAcc.LastName, &UserAcc.PhoneNumber, &UserAcc.Email)
	if err != nil {
		return UserAcc, err
	}
	return UserAcc, nil
}

// to get all data from the table
func (UserAccDb_Model *UserAccountsDbModel) All() ([]models.UserAccount, error) {
	statement := `SELECT id, user_name, first_name, last_name, phone_number, email FROM user_accounts ORDER BY id DESC;`

	rows, err := UserAccDb_Model.DB.Query(statement)
	if err != nil {
		return nil, err
	}
	//initializing the empty slice <UserAccounts> of data type <models.UserAccount>
	UserAccounts := []models.UserAccount{}
	for rows.Next() {
		// initializing the empty variable <UserAccounts> of data type <models.UserAccount>
		UserAcc := models.UserAccount{}
		//extracting data from rows and setting in UserAcc Variable
		err := rows.Scan(&UserAcc.ID, &UserAcc.UserName, &UserAcc.FirstName, &UserAcc.LastName, &UserAcc.PhoneNumber, &UserAcc.Email)
		if err != nil {
			return nil, err
		}

		// finally adding that single user account data
		// as element in slice UserAccounts
		UserAccounts = append(UserAccounts, UserAcc)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	// final return
	return UserAccounts, nil
}

// Insert Data in table
func (UserAccDb_Model *UserAccountsDbModel) Insert(user_name, first_name, last_name, phone_number, email string) (rowAffected int64, err error) {
	statement := `INSERT INTO user_accounts (user_name, first_name, last_name, phone_number, email) VALUES (?, ?, ?, ?, ?);`

	// use exec when there is no return
	result, err := UserAccDb_Model.DB.Exec(statement, user_name, first_name, last_name, phone_number, email)
	if err != nil {
		return rowAffected, err
	}

	// getting row affected from the result
	rowAffected, err = result.RowsAffected()
	if err != nil {
		return rowAffected, err
	}
	return rowAffected, nil
}

// Update Data in table
func (UserAccDb_Model *UserAccountsDbModel) Update(user_name, first_name, last_name, phone_number, email string) (rowAffected int64, err error) {
	statement := `UPDATE user_accounts SET first_name = ?, last_name = ?, phone_number = ?, email = ? WHERE user_name = ?`

	// use exec when there is no return
	result, err := UserAccDb_Model.DB.Exec(statement, first_name, last_name, phone_number, email, user_name)
	if err != nil {
		return rowAffected, err
	}

	// getting row affected from the result
	rowAffected, err = result.RowsAffected()
	if err != nil {
		return rowAffected, err
	}
	return rowAffected, nil
}

// Delete Data in table
func (UserAccDb_Model *UserAccountsDbModel) Delete(user_name string) (rowAffected int64, err error) {
	statement := `DELETE FROM user_accounts WHERE user_name = ?;`

	// use exec when there is no return
	result, err := UserAccDb_Model.DB.Exec(statement, user_name)
	if err != nil {
		return rowAffected, err
	}

	// getting row affected from the result
	rowAffected, err = result.RowsAffected()
	if err != nil {
		return rowAffected, err
	}
	return rowAffected, nil
}

// =============================================================================================== //
// =============================================================================================== //
// =============================================================================================== //
// =============================================================================================== //
// =============================================================================================== //
// user table manipulation
// Insert Data in table
func (UserAccDb_Model *UserAccountsDbModel) SignUpUserQuery(email, password string) (int64, error) {
	statement := `INSERT INTO users (email, password) VALUES (?, ?);`

	// use exec when there is no return
	result, err := UserAccDb_Model.DB.Exec(statement, email, password)
	if err != nil {
		return 0, err
	}

	// getting row affected from the result
	rowAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rowAffected, nil
}

func (UserAccDb_Model *UserAccountsDbModel) LoginUserQuery(email string) (user models.User, err error) {
	statement := `SELECT email, password FROM users WHERE email = ?`

	err = UserAccDb_Model.DB.QueryRow(statement, email).Scan(&user.Email, &user.Password)
	if err != nil {
		return user, err
	}
	return user, nil
}

func (UserAccDb_Model *UserAccountsDbModel) RefreshTokenInsertQuery(refresh_token string, email string) (int64, error) {
	statement := `UPDATE users SET refresh_token = ? WHERE email = ?;`

	// use exec when there is no return
	result, err := UserAccDb_Model.DB.Exec(statement, refresh_token, email)
	if err != nil {
		return 0, err
	}

	// getting row affected from the result
	rowAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rowAffected, nil
}

func (UserAccDb_Model *UserAccountsDbModel) GetUserByEmailQuery(email string) (user models.User, err error) {
	statement := `SELECT email, password FROM users WHERE email = ?`

	err = UserAccDb_Model.DB.QueryRow(statement, email).Scan(&user.Email, &user.Password)
	if err != nil {
		return user, err
	}
	return user, nil
}

func (UserAccDb_Model *UserAccountsDbModel) GetUserRefreshTokenQuery(refresh_token string) (user models.User, err error) {
	statement := `SELECT email, password FROM users WHERE refresh_token = ?`

	err = UserAccDb_Model.DB.QueryRow(statement, refresh_token).Scan(&user.Email, &user.Password)
	if err != nil {
		return user, err
	}
	return user, nil
}

func (UserAccDb_Model *UserAccountsDbModel) RefreshTokenDeleteQuery(refresh_token string) (int64, error) {
	// here we can delete whole row as it have other field too :)
	statement := `UPDATE users SET refresh_token = NULL WHERE refresh_token = ?;`

	// use exec when there is no return
	result, err := UserAccDb_Model.DB.Exec(statement, refresh_token)
	if err != nil {
		return 0, err
	}

	// getting row affected from the result
	rowAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rowAffected, nil
}

// =============================================================================================== //
// =============================================================================================== //
// =============================================================================================== //
// =============================================================================================== //
// =============================================================================================== //
// users_github table manipulation

// func (db *UserAccountsDbModel) UpsertGithubUser(githubID int64, email, name, avatarURL, username, accessToken, refreshToken string) (rowAffected int64, err error) {
func (db *UserAccountsDbModel) InsertOrUpdateGithubUserQuery(userGitHub models.UserGitHub) (rowAffected int64, err error) {
	var count int
	err = db.DB.QueryRow("SELECT COUNT(*) FROM users_github WHERE github_id = ?", userGitHub.GitHubID).Scan(&count)
	// err = db.DB.QueryRow("SELECT COUNT(*) FROM users_github WHERE github_id = ?", githubID).Scan(&count)
	if err != nil {
		return 0, err
	}

	if count == 0 {
		// Insert new user
		statement := `
		INSERT INTO users_github (github_id, email, name, avatar_url, github_username, github_access_token, refresh_token)
		VALUES (?, ?, ?, ?, ?, ?, ?);
		`
		result, err := db.DB.Exec(statement, userGitHub.GitHubID, userGitHub.Email, userGitHub.Name, userGitHub.AvatarURL, userGitHub.GitHubUsername, userGitHub.GitHubAccessToken, userGitHub.RefreshToken)
		// result, err := db.DB.Exec(statement, githubID, email, name, avatarURL, username, accessToken, refreshToken)
		if err != nil {
			return 0, err
		}
		rowAffected, err = result.RowsAffected()
		if err != nil {
			return 0, err
		}
	} else {
		// Update existing user
		statement := `
		UPDATE users_github 
		SET email = ?, name = ?, avatar_url = ?, github_username = ?, github_access_token = ?, refresh_token = ?
		WHERE github_id = ?;
		`
		result, err := db.DB.Exec(statement, userGitHub.GitHubID, userGitHub.Email, userGitHub.Name, userGitHub.AvatarURL, userGitHub.GitHubUsername, userGitHub.GitHubAccessToken, userGitHub.RefreshToken)
		// result, err := db.DB.Exec(statement, email, name, avatarURL, username, accessToken, refreshToken, githubID)
		if err != nil {
			return 0, err
		}
		rowAffected, err = result.RowsAffected()
		if err != nil {
			return 0, err
		}
	}

	return rowAffected, nil
}

func (UserAccDb_Model *UserAccountsDbModel) GetUserIDByGitHubID(githubID int) (id int, err error) {
	statement := `SELECT id FROM users_github WHERE github_id = ?`
	err = UserAccDb_Model.DB.QueryRow(statement, githubID).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, err
			// return 0, fmt.Errorf("no user found with github_id: %d", githubID)
		}
		return 0, err
	}
	return id, nil
}

func (UserAccDb_Model *UserAccountsDbModel) GetUserByIdQuery(id int) (userGitHub models.UserGitHubWithoutRefreshAndAcess, err error) {
	// statement := `SELECT id, github_id, email, name, avatar_url, github_username, github_access_token, refresh_token FROM users_github WHERE id = ?`
	statement := `SELECT id, github_id, email, name, avatar_url, github_username FROM users_github WHERE id = ?`

	// err = UserAccDb_Model.DB.QueryRow(statement, github_id).Scan(&UserAcc.ID, &UserAcc.UserName, &UserAcc.FirstName, &UserAcc.LastName, &UserAcc.PhoneNumber, &UserAcc.Email)
	err = UserAccDb_Model.DB.QueryRow(statement, id).Scan(&userGitHub.ID, &userGitHub.GitHubID, &userGitHub.Email, &userGitHub.Name, &userGitHub.AvatarURL, &userGitHub.GitHubUsername)
	if err != nil {
		return userGitHub, err
	}
	return userGitHub, nil
}

func (UserAccDb_Model *UserAccountsDbModel) GetUserByRefreshTokenQuery(refresh_token string) (userGitHub models.UserGitHub, err error) {
	statement := `SELECT id, github_id, email, name, avatar_url, github_username, github_access_token, refresh_token FROM users_github WHERE refresh_token = ?`

	err = UserAccDb_Model.DB.QueryRow(statement, refresh_token).Scan(userGitHub.ID, &userGitHub.GitHubID, &userGitHub.Email, &userGitHub.Name, &userGitHub.AvatarURL, &userGitHub.GitHubUsername, &userGitHub.GitHubAccessToken, &userGitHub.RefreshToken)
	if err != nil {
		return userGitHub, err
	}
	return userGitHub, nil
}
