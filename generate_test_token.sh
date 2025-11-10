#!/bin/bash

# Generate a fresh JWT token for testing
# Uses the JWT_SECRET_KEY from dev.env

# Source the dev environment
source configs/dev.env

# Generate token
echo "Generating fresh JWT token..."
JWT_SECRET_KEY=$JWT_SECRET_KEY go run tools/generate_jwt_token.go

echo -e "\n\nTo test with this token:"
echo 'curl -s http://localhost:6001/get_products -H "Authorization: Bearer <TOKEN>" | jq .'
