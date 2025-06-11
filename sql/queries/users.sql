-- name: CreateUser :one
INSERT INTO users (id, email, hashed_password, is_chirpy_red, created_at, updated_at)
VALUES ($1, $2, $3, false, NOW(), NOW())
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE email = $1;

-- name: UpdateUser :one
UPDATE users
SET email = $2,
    hashed_password = $3,
    is_chirpy_red = $4,
    updated_at = NOW()
WHERE id = $1
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: UpgradeUserToChirpyRed :exec
UPDATE users
SET is_chirpy_red = true,
    updated_at = NOW()
WHERE id = $1;

