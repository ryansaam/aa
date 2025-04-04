package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/ryansaam/aa/db"
	"github.com/ryansaam/aa/utils"
	"golang.org/x/crypto/bcrypt"
)

// LoginUser handles authenticating a user and issuing a new refresh token.
// It expects a JSON body containing an email and password.
func LoginUser(write http.ResponseWriter, request *http.Request, ctx context.Context, queries *db.Queries) {
	internalServerErrorMsg := "Sorry, we're having trouble processing your request. Try again later."

	// Parse login data.
	type LoginInfo struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	loginInfo := LoginInfo{}
	if err := json.NewDecoder(request.Body).Decode(&loginInfo); err != nil {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "Invalid request body.")
		return
	}

	// check user input
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(loginInfo.Email) {
		write.WriteHeader(http.StatusUnauthorized)
		writeResponse(write, []byte{}, "email_password_error")
		return
	}

	if !isValidPassword(loginInfo.Password) {
		write.WriteHeader(http.StatusUnauthorized)
		writeResponse(write, []byte{}, "email_password_error")
		return
	}

	// Retrieve the authentic user from the database using email.
	authenticUser, err := queries.GetAuthenticUserWithEmail(ctx, loginInfo.Email)
	if err != nil && err == sql.ErrNoRows {
		write.WriteHeader(http.StatusUnauthorized)
		writeResponse(write, []byte{}, "email_password_error")
		return
	}
	if err != nil {
		log.Printf("Failed to get authentic user with email: LoginUser() -> queries.GetAuthenticUserWithEmail(); error: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		return
	}

	// Compare the provided password with the stored bcrypt hash.
	if err := bcrypt.CompareHashAndPassword([]byte(authenticUser.Password), []byte(loginInfo.Password)); err != nil {
		write.WriteHeader(http.StatusUnauthorized)
		writeResponse(write, []byte{}, "email_password_error")
		return
	}

	// Create a new refresh token.
	userID, err := uuid.Parse(authenticUser.ID.String())
	if err != nil {
		log.Printf("Could not parse user ID: LoginUser() -> uuid.Parse(); error: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		writeAccessTokenResponse(write, []byte{}, internalServerErrorMsg)
		return
	}
	encryptedToken, jti, exp, err := utils.CreateEncryptedRefreshToken(userID)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to generate and encrypt refresh token: LoginUser() -> utils.CreateEncryptedRefreshToken(); error: %v\n", err)
		return
	}

	// Insert the new refresh token into the database.
	if err := utils.InsertRefreshTokenForUser(authenticUser.ID.String(), jti, exp, ctx, queries); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert refresh token: LoginUser() -> utils.InsertRefreshTokenForUser(); error: %v\n", err)
		return
	}

	// Attempt to extract the old refresh token from the secure cookie.
	claims, err := utils.ExtractRefreshTokenClaims(request)
	if err != nil {
		// If the error is due to a missing cookie, log and skip revocation.
		if strings.Contains(err.Error(), "failed to retrieve refresh token cookie") {
			log.Printf("No existing refresh token cookie found; skipping token revocation.")
		} else {
			// For other errors, treat it as an unauthorized request.
			write.Header().Set("WWW-Authenticate", "Bearer")
			write.WriteHeader(http.StatusUnauthorized)
			writeAccessTokenResponse(write, []byte{}, "Unauthorized request")
			return
		}
	} else {
		// If a previous refresh token exists, revoke it by adding it to the blacklist.
		oldJti, err := uuid.Parse(claims.RegisteredClaims.ID)
		if err != nil {
			log.Printf("Could not parse token jti: LoginUser() -> uuid.Parse(); error: %v\n", err)
			write.WriteHeader(http.StatusInternalServerError)
			writeAccessTokenResponse(write, []byte{}, internalServerErrorMsg)
			return
		}

		var tokenExpTime time.Time
		if claims.RegisteredClaims.ExpiresAt != nil {
			tokenExpTime = claims.RegisteredClaims.ExpiresAt.Time
		} else {
			tokenExpTime = time.Now()
		}
		blacklistParams := db.InsertTokenToBlackListParams{
			Jti: *utils.UUIDToPgUUID(oldJti),
			Exp: pgtype.Timestamptz{Time: tokenExpTime, Valid: true},
		}
		err = queries.InsertTokenToBlackList(ctx, blacklistParams)
		if err != nil {
			log.Printf("Could not revoke refresh token: LoginUser() -> queries.InsertTokenToBlackList(); error: %v\n", err)
			write.WriteHeader(http.StatusInternalServerError)
			writeResponse(write, []byte{}, internalServerErrorMsg)
			return
		}
	}

	isLocalhost := strings.Contains(request.Host, "localhost")
	// Set encrypted refresh token as a secure, HttpOnly cookie.
	http.SetCookie(write, &http.Cookie{
		Name:     "refresh_token",
		Value:    utils.Encode64(encryptedToken),
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   !isLocalhost,
		SameSite: http.SameSiteStrictMode,
	})

	// Return 200 with no token in response body.
	write.WriteHeader(http.StatusOK)
	writeResponse(write, nil, "")
}
