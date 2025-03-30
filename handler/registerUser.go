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
		log.Printf("Failed to decode request body; RegisterUser(); error: %v\n", err)
		return
	}

	// Validate first and last name
	nameRegex := regexp.MustCompile(`^[a-zA-Z](?:[a-zA-Z\s]{0,13}[a-zA-Z])?$`)
	if !nameRegex.MatchString(registerInfo.Firstname) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "First name format not allowed.")
		log.Printf("Invalid first name format; RegisterUser(); firstname: %s\n", registerInfo.Firstname)
		return
	}
	if !nameRegex.MatchString(registerInfo.Lastname) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "Last name format not allowed.")
		log.Printf("Invalid last name format; RegisterUser(); lastname: %s\n", registerInfo.Lastname)
		return
	}

	// Check password complexity
	if !isValidPassword(registerInfo.Password) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "Password format not allowed.")
		log.Printf("Invalid password format; RegisterUser(); email: %s\n", registerInfo.Email)
		return
	}

	// Hash password
	password := []byte(registerInfo.Password)
	secondaryID := uuid.New()
	salt := []byte(secondaryID.String())

	passwordHash, err := scrypt.Key(password, salt, 32768, 8, 2, 32)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to hash password; RegisterUser(); error: %v; email: %s\n", err, registerInfo.Email)
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
		log.Printf("Failed to insert unverified user; RegisterUser(); error: %v; email: %s\n", err, registerInfo.Email)
		return
	}

	newUserParams := db.InsertNewUserParams{
		ID:        *utils.UUIDToPgUUID(userId),
		Firstname: strings.ToLower(registerInfo.Firstname),
		Lastname:  strings.ToLower(registerInfo.Lastname),
		Email:     registerInfo.Email,
		Password:  fmt.Sprintf("%x", passwordHash),
	}

	if err := queries.InsertNewUser(ctx, newUserParams); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert new user; RegisterUser(); error: %v; email: %s\n", err, registerInfo.Email)
		return
	}

	// Create refresh token
	jti, err := uuid.NewRandom()
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to generate JTI UUID; RegisterUser(); error: %v\n", err)
		return
	}

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
		log.Printf("Failed to sign refresh token; RegisterUser(); error: %v; userID: %s\n", err, userId.String())
		return
	}

	// Store refresh token in DB
	if err := utils.InsertRefreshTokenForUser(userId.String(), jti.String(), exp, ctx, queries); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert refresh token; RegisterUser(); error: %v; userID: %s\n", err, userId.String())
		return
	}

	// Encrypt the refresh token
	encryptedRefreshToken, internalErr, err := utils.Encrypt([]byte(refreshToken), []byte(os.Getenv("CIPHER_KEY")))
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to encrypt refresh token; RegisterUser(); error: %v; internalErr: %v; userID: %s\n", err, internalErr, userId.String())
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
