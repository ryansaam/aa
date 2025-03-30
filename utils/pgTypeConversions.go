package utils

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func UUIDToPgUUID(id uuid.UUID) *pgtype.UUID {
	var retId pgtype.UUID
	copy(retId.Bytes[:], id[:])
	retId.Valid = true
	return &retId
}
