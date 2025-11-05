-- name: CreateMediaBuy :execresult
INSERT INTO media_buys (buyer_ref, brand_url, start_time, end_time) -- VALUES ($1, $2, $3, $4);
VALUES (?, ?, ?, ?);
-- 
-- name: CreatePackage :execresult
INSERT INTO packages (
        media_buy_id,
        buyer_ref,
        product_id,
        pricing_option_id,
        format_ids_json,
        budget,
        pacing
    ) -- VALUES ($1, $2, $3, $4, $5, $6, $7);
VALUES (?, ?, ?, ?, ?, ?, ?);
-- 
-- name: GetMediaBuy :one
SELECT *
FROM media_buys
WHERE id = ?;
-- 
-- name: ListMediaBuys :many
SELECT *
FROM media_buys
ORDER BY id DESC
LIMIT ? OFFSET ?;
-- 
-- name: GetPackagesByMediaBuy :many
SELECT *
FROM packages
WHERE media_buy_id = ?;
--
-- name: CountMediaBuys :one
SELECT count(*)
FROM media_buys;