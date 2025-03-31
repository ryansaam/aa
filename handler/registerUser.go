package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/ryansaam/aa/db"
	"github.com/ryansaam/aa/utils"
)

func isValidPassword(password string) bool {
	// Check length
	if len(password) < 8 {
		return false
	}

	hasUppercase := false
	hasNumber := false

	// Check for at least one uppercase letter and one number
	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUppercase = true
		} else if unicode.IsDigit(char) {
			hasNumber = true
		}

		// Break the loop early if both conditions are satisfied
		if hasUppercase && hasNumber {
			break
		}
	}

	return hasUppercase && hasNumber
}

func writeResponse(write http.ResponseWriter, encryptedRefreshToken []byte, errMessage string) {
	write.Header().Set("Content-Type", "application/json")

	type Response struct {
		RefreshToken string `json:"refresh_token"`
		Error        string `json:"error"`
	}

	response := Response{
		RefreshToken: utils.Encode64(encryptedRefreshToken),
		Error:        errMessage,
	}

	if err := json.NewEncoder(write).Encode(response); err != nil {
		log.Printf("Error encoding response: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		write.Write([]byte(`{"error": "unexpected server error"}`))
	}
}

// RegisterUser handles new account creation, password hashing, user and unverified inserts, and refresh token issuance.
func RegisterUser(write http.ResponseWriter, request *http.Request, ctx context.Context, queries *db.Queries, dbpool *pgxpool.Pool) {
	internalServerErrorMsg := "Sorry, we're having trouble processing your request. Try again later."

	// Parse request body
	type RegisterInfo struct {
		Firstname string `json:"firstname"`
		Lastname  string `json:"lastname"`
		Password  string `json:"password"`
		Email     string `json:"email"`
	}

	registerInfo := RegisterInfo{}
	if err := json.NewDecoder(request.Body).Decode(&registerInfo); err != nil {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "Invalid request body.")
		return
	}

	// Validate first and last name
	nameRegex := regexp.MustCompile(`^[a-zA-Z](?:[a-zA-Z\s]{0,13}[a-zA-Z])?$`)
	if !nameRegex.MatchString(registerInfo.Firstname) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "First name format not allowed.")
		return
	}
	if !nameRegex.MatchString(registerInfo.Lastname) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "Last name format not allowed.")
		return
	}

	// Validate email
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(registerInfo.Email) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "Invalid email format.")
		return
	}

	// Check password complexity
	if !isValidPassword(registerInfo.Password) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "Password format not allowed.")
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerInfo.Password), bcrypt.DefaultCost)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to hash password with bcrypt: %v", err)
		return
	}

	userId := uuid.New()

	// Begin transaction
	tx, err := dbpool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to begin transaction; RegisterUser() -> BeginTx(); error: %v", err)
		return
	}
	defer tx.Rollback(ctx)

	txQueries := db.New(tx)

	unverifiedParams := db.InsertUnverifiedUserParams{
		ID:               *utils.UUIDToPgUUID(userId),
		Email:            registerInfo.Email,
		VerificationCode: "",
	}

	if err := txQueries.InsertUnverifiedUser(ctx, unverifiedParams); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert unverified user; RegisterUser() -> queries.InsertUnverifiedUser(); error: %v", err)
		return
	}

	newUserParams := db.InsertNewUserParams{
		ID:        *utils.UUIDToPgUUID(userId),
		Firstname: strings.ToLower(registerInfo.Firstname),
		Lastname:  strings.ToLower(registerInfo.Lastname),
		Email:     registerInfo.Email,
		Password:  string(hashedPassword),
	}

	if err := txQueries.InsertNewUser(ctx, newUserParams); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert new user; RegisterUser() -> queries.InsertNewUser(); error: %v", err)
		return
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to commit transaction; error: %v", err)
		return
	}

	// Create refresh token
	encryptedToken, jti, exp, err := utils.CreateEncryptedRefreshToken(userId)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to generate and encrypt refresh token: %v", err)
		return
	}

	if err := utils.InsertRefreshTokenForUser(userId.String(), jti, exp, ctx, queries); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert refresh token; RegisterUser() -> utils.InsertRefreshTokenForUser(); error: %v\n", err)
		return
	}

	write.WriteHeader(http.StatusOK)
	writeResponse(write, encryptedToken, "")
}

// // construct and fire mixpanel event
// type MixpanelEventProperties struct {
// 	Time       int64  `json:"time"`
// 	DistinctID string `json:"distinct_id"`
// 	InsertID   string `json:"$insert_id"`
// 	IP         string `json:"ip"`
// 	Action     string `json:"action"`
// }
// type MixpanelEvent struct {
// 	Event      string                  `json:"event"`
// 	Properties MixpanelEventProperties `json:"properties"`
// }
// event := MixpanelEvent{
// 	Event: "AA",
// 	Properties: MixpanelEventProperties{
// 		Time:       time.Now().Unix(),
// 		DistinctID: unverifiedUser.ID.String(),
// 		InsertID:   uuid.New().String(),
// 		IP:         strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0],
// 		Action:     "registration completed",
// 	},
// }
// log.Printf("IP: %s", strings.Split(request.Header.Get("X-Forwarded-For"), ",")[0])
// go utils.FireMixpanelEvent([]MixpanelEvent{event})
