#!/bin/bash

# PostgreSQL Configuration
DB_NAME="webscanner"
DB_USER="postgres"
DB_PASSWORD="admin"
DB_HOST="localhost"
DB_PORT="5432"
TABLE_NAME="scan_requests"

# Export password for non-interactive authentication
export PGPASSWORD="$DB_PASSWORD"

# Drop the table if it exists
psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c "DROP TABLE IF EXISTS $TABLE_NAME CASCADE;"

# Unset password variable for security
unset PGPASSWORD
