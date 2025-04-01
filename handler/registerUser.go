package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stripe/stripe-go/v81"
	"github.com/stripe/stripe-go/v81/customer"
	"github.com/stripe/stripe-go/v81/paymentmethod"
	"github.com/stripe/stripe-go/v81/subscription"
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
		Error: errMessage,
	}
	if encryptedRefreshToken != nil {
		response.RefreshToken = utils.Encode64(encryptedRefreshToken)
	}

	if err := json.NewEncoder(write).Encode(response); err != nil {
		log.Printf("Error encoding response: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		write.Write([]byte(`{"error": "unexpected server error"}`))
	}
}

// RegisterUser handles new account creation, password hashing, user and unverified inserts,
// Stripe customer/subscription creation, and refresh token issuance.
func RegisterUser(write http.ResponseWriter, request *http.Request, ctx context.Context, queries *db.Queries, dbpool *pgxpool.Pool) {
	internalServerErrorMsg := "Sorry, we're having trouble processing your request. Try again later."

	// Parse request body
	type RegisterInfo struct {
		Firstname     string `json:"firstname"`
		Lastname      string `json:"lastname"`
		Password      string `json:"password"`
		Email         string `json:"email"`
		BillingName   string `json:"billing_name"`
		PaymentMethod string `json:"payment_method"`
		Address       string `json:"address"`
		Apartment     string `json:"apartment"`
		City          string `json:"city"`
		State         string `json:"state"`
		Zip           string `json:"zip"`
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
		writeResponse(write, []byte{}, "first_name_not_allowed")
		return
	}
	if !nameRegex.MatchString(registerInfo.Lastname) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "last_name_not_allowed")
		return
	}

	// Validate email
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(registerInfo.Email) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "email_not_allowed")
		return
	}

	// Check password complexity
	if !isValidPassword(registerInfo.Password) {
		write.WriteHeader(http.StatusBadRequest)
		writeResponse(write, []byte{}, "password_not_allowed")
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerInfo.Password), bcrypt.DefaultCost)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to hash password with bcrypt: RegisterUser() -> bcrypt.GenerateFromPassword(); error: %v\n", err)
		return
	}

	userId := uuid.New()

	// Begin transaction (we'll include stripe info insertion in this transaction)
	tx, err := dbpool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to begin transaction; RegisterUser() -> dbpool.BeginTx(); error: %v\n", err)
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
		log.Printf("Failed to insert unverified user: RegisterUser() -> txQueries.InsertUnverifiedUser(); error: %v\n", err)
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
		log.Printf("Failed to insert new user: RegisterUser() -> txQueries.InsertNewUser(); error: %v\n", err)
		return
	}

	// --- Begin Stripe integration (inside transaction) ---

	// Set Stripe secret key (ideally load from environment)
	stripe.Key = os.Getenv("STRIPE_PRIVATE_KEY")

	// Create a new Stripe customer using billing info
	custParams := &stripe.CustomerParams{
		Email: stripe.String(registerInfo.Email),
		Name:  stripe.String(registerInfo.BillingName),
		Address: &stripe.AddressParams{
			Line1:      stripe.String(registerInfo.Address),
			Line2:      stripe.String(registerInfo.Apartment),
			City:       stripe.String(registerInfo.City),
			State:      stripe.String(registerInfo.State),
			PostalCode: stripe.String(registerInfo.Zip),
			Country:    stripe.String("US"),
		},
	}
	cust, err := customer.New(custParams)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to create Stripe customer: RegisterUser() -> customer.New(); error: %v\n", err)
		return
	}

	// Attach the PaymentMethod to the customer
	_, err = paymentmethod.Attach(
		registerInfo.PaymentMethod,
		&stripe.PaymentMethodAttachParams{
			Customer: stripe.String(cust.ID),
		},
	)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to attach PaymentMethod to customer: RegisterUser() -> paymentmethod.Attach(); error: %v\n", err)
		return
	}

	// Create a subscription for the customer
	subParams := &stripe.SubscriptionParams{
		Customer: stripe.String(cust.ID),
		Items: []*stripe.SubscriptionItemsParams{
			{
				Price: stripe.String("price_1R8rvCERw22WyhJUKBT0bcAl"),
			},
		},
		DefaultPaymentMethod: stripe.String(registerInfo.PaymentMethod),
	}
	subObj, err := subscription.New(subParams)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to create subscription: RegisterUser() -> subscription.New(); error: %v\n", err)
		return
	}

	// Insert Stripe info into database as part of the transaction
	stripeInfoParams := db.InsertStripeInfoParams{
		UserID:                *utils.UUIDToPgUUID(userId),
		StripeCustomerID:      cust.ID,
		StripeSubscriptionID:  subObj.ID,
		StripePaymentMethodID: registerInfo.PaymentMethod,
	}
	if err := txQueries.InsertStripeInfo(ctx, stripeInfoParams); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert stripe info: RegisterUser() -> txQueries.InsertStripeInfo(); error: %v\n", err)
		return
	}

	// --- End Stripe integration ---

	// Commit transaction (this commits user, unverified user, and stripe info together)
	if err := tx.Commit(ctx); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to commit transaction: RegisterUser() -> tx.Commit(); error: %v\n", err)
		return
	}

	// Create refresh token
	encryptedToken, jti, exp, err := utils.CreateEncryptedRefreshToken(userId)
	if err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to generate and encrypt refresh token: RegisterUser() -> utils.CreateEncryptedRefreshToken(); error: %v\n", err)
		return
	}

	if err := utils.InsertRefreshTokenForUser(userId.String(), jti, exp, ctx, queries); err != nil {
		write.WriteHeader(http.StatusInternalServerError)
		writeResponse(write, []byte{}, internalServerErrorMsg)
		log.Printf("Failed to insert refresh token: RegisterUser() -> utils.InsertRefreshTokenForUser(); error: %v\n", err)
		return
	}

	isLocalhost := strings.Contains(request.Host, "localhost")
	// Set encrypted refresh token as a secure, HttpOnly cookie
	http.SetCookie(write, &http.Cookie{
		Name:     "refresh_token",
		Value:    utils.Encode64(encryptedToken),
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   !isLocalhost,
		SameSite: http.SameSiteStrictMode,
	})

	// Return 200 with no token in response body
	write.WriteHeader(http.StatusOK)
	writeResponse(write, nil, "")
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
