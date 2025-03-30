-- name: InsertRefreshToken :exec
INSERT INTO issued_refresh_tokens 
(sub, jti, exp) 
VALUES ($1, $2, $3);

-- name: InsertNewUser :exec
INSERT INTO users
(id, secondary_id, firstname, lastname, email, password)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: InsertUnverifiedUser :exec
INSERT INTO unverified_users
(id, email, verification_code)
VALUES ($1, $2, $3);