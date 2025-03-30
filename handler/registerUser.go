package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"

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
		log.Fatalf("Error encoding response: %s\n", err)
	}
}

func RegisterUser(write http.ResponseWriter, request *http.Request, ctx context.Context, queries *db.Queries) {
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
	password := []byte(registerInfo.Password)
	secondaryID := uuid.New()
	salt := []byte(secondaryID.String())

	passwordHash, err := scrypt.Key(password, salt, 1<<17, 8, 1, 64)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to hash password; RegisterUser() -> scrypt.Key(); error: %v", err)
		return
	}

	userId := uuid.New()
	unverifiedParams := db.InsertUnverifiedUserParams{
		ID:               *utils.UUIDToPgUUID(userId),
		Email:            registerInfo.Email,
		VerificationCode: "",
	}

	if err := queries.InsertUnverifiedUser(ctx, unverifiedParams); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert unverified user; RegisterUser() -> queries.InsertUnverifiedUser(); error: %v", err)
		return
	}

	newUserParams := db.InsertNewUserParams{
		ID:          *utils.UUIDToPgUUID(userId),
		SecondaryID: *utils.UUIDToPgUUID(secondaryID),
		Firstname:   strings.ToLower(registerInfo.Firstname),
		Lastname:    strings.ToLower(registerInfo.Lastname),
		Email:       registerInfo.Email,
		Password:    fmt.Sprintf("%x", passwordHash),
	}

	if err := queries.InsertNewUser(ctx, newUserParams); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert new user; RegisterUser() -> queries.InsertNewUser(); error: %v", err)
		return
	}

	// Create refresh token
	jti := uuid.New()
	exp := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Millisecond)
	now := time.Now().Truncate(time.Millisecond)

	claims := &utils.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userId.String(),
			ExpiresAt: &jwt.NumericDate{Time: exp},
			ID:        jti.String(),
			Issuer:    "Knomor AA service",
			IssuedAt:  &jwt.NumericDate{Time: now},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	refreshToken, err := token.SignedString([]byte(os.Getenv("REFRESH_TOKEN_SECRET")))
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to sign refresh token; RegisterUser() -> token.SignedString(); error: %v\n", err)
		return
	}

	// Store refresh token in DB
	if err := utils.InsertRefreshTokenForUser(userId.String(), jti.String(), exp, ctx, queries); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert refresh token; RegisterUser() -> utils.InsertRefreshTokenForUser(); error: %v\n", err)
		return
	}

	// Encrypt the refresh token
	encryptedRefreshToken, internalErr, err := utils.Encrypt([]byte(refreshToken), []byte(os.Getenv("CIPHER_KEY")))
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to encrypt refresh token; RegisterUser() -> utils.Encrypt(); error: %v; internalErr: %v\n", err, internalErr)
		return
	}

	write.WriteHeader(http.StatusOK)
	writeResponse(write, encryptedRefreshToken, "")
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
