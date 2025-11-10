#!/bin/bash

# Test pricing visibility with authentication

echo "1. Testing without authentication:"
curl -s http://localhost:8081/get_products | jq '{
  limited: .limited_results,
  message: .message,
  first_product: .products[0] | {
    id: .product_id,
    name: .name,
    has_cpm: (has("cpm")),
    cpm: .cpm,
    has_pricing_options: (has("pricing_options"))
  }
}'

echo -e "\n2. Testing with API Key:"
curl -s http://localhost:8081/get_products \
  -H "X-API-Key: test_api_key_full_access" | jq '{
  limited: .limited_results,
  message: .message,
  first_product: .products[0] | {
    id: .product_id,
    name: .name,
    has_cpm: (has("cpm")),
    cpm: .cpm,
    has_pricing_options: (has("pricing_options")),
    pricing_options_count: (.pricing_options | length)
  }
}'

echo -e "\n3. Testing with JWT Bearer token:"
JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhZHRlLXNhbGVzLWFnZW50Iiwic3ViIjoicHJpbmNpcGFsX3Rlc3QiLCJleHAiOjE3NjI4NzY2OTYsIm5iZiI6MTc2Mjc5MDI5NiwiaWF0IjoxNzYyNzkwMjk2LCJwZXJtaXNzaW9ucyI6eyJwcm9kdWN0cyI6WyJyZWFkIl0sIm1lZGlhX2J1eXMiOlsicmVhZCIsIndyaXRlIl0sImNyZWF0aXZlcyI6WyJyZWFkIiwid3JpdGUiXSwicmVwb3J0cyI6WyJyZWFkIiwid3JpdGUiXX19.dK7CYyrFcWPBqGiu0gN44wc5uZGw0ahZZhO7RESVy8o"

curl -s http://localhost:6001/get_products \
  -H "Authorization: Bearer $JWT" | jq '{
  limited: .limited_results,
  message: .message,
  first_product: .products[0] | {
    id: .product_id,
    name: .name,
    has_cpm: (has("cpm")),
    cpm: .cpm,
    has_pricing_options: (has("pricing_options")),
    pricing_options_count: (.pricing_options | length)
  }
}'
