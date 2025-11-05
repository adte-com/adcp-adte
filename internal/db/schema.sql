-- Media buys table
CREATE TABLE IF NOT EXISTS media_buys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    buyer_ref TEXT,
    brand_url TEXT,
    start_time TEXT,
    end_time TEXT,
    status TEXT DEFAULT 'pending' CHECK(
        status IN (
            'pending',
            'active',
            'paused',
            'completed',
            'cancelled'
        )
    ),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- 
-- Packages table
CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    media_buy_id INTEGER NOT NULL,
    buyer_ref TEXT,
    product_id TEXT,
    pricing_option_id TEXT,
    format_ids_json TEXT,
    budget REAL,
    spent REAL DEFAULT 0,
    pacing TEXT,
    status TEXT DEFAULT 'pending' CHECK(
        status IN (
            'pending',
            'active',
            'paused',
            'completed',
            'cancelled'
        )
    ),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(media_buy_id) REFERENCES media_buys(id) ON DELETE CASCADE
);
-- 
-- Indexes for performance optimization
CREATE INDEX idx_media_buys_buyer_ref ON media_buys(buyer_ref);
CREATE INDEX idx_packages_media_buy_id ON packages(media_buy_id);
CREATE INDEX idx_packages_product_id ON packages(product_id);