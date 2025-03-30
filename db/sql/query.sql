-- name: InsertRefreshToken :exec
INSERT INTO issued_refresh_tokens 
(sub, jti, exp) 
VALUES ($1, $2, $3);

-- name: InsertNewUser :exec
INSERT INTO users
(id, firstname, lastname, email, password)
VALUES ($1, $2, $3, $4, $5);

-- name: InsertUnverifiedUser :exec
INSERT INTO unverified_users
(id, email, verification_code)
VALUES ($1, $2, $3);