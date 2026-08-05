'use strict';
const Database = require('better-sqlite3');

const db = new Database(':memory:');
db.exec(`
  CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT,
    category TEXT,
    price REAL
  );
  INSERT INTO products (name, category, price) VALUES
    ('Wireless Mouse',    'peripherals', 24.99),
    ('Mechanical Keyboard','peripherals', 89.99),
    ('27" 4K Monitor',    'displays',    329.99),
    ('USB-C Hub',         'accessories', 39.99),
    ('Laptop Stand',      'accessories', 29.99),
    ('Admin Panel License','software',   0.00);
`);

/** VULNERABLE: raw string interpolation into SQL */
function searchProducts(q) {
  const sql = `SELECT * FROM products WHERE name LIKE '%${q}%' OR category LIKE '%${q}%'`;
  return db.prepare(sql).all();
}

function getAllProducts() {
  return db.prepare('SELECT * FROM products').all();
}

// ---- mini "Mongo-like" engine (operator-injection demo) ----
const users = [
  { id: 1, username: 'admin', password: 'S3cret!', role: 'admin' },
  { id: 2, username: 'alice', password: 'wonderland', role: 'staff' },
  { id: 3, username: 'bob',   password: 'builder',   role: 'user'  },
];

function matches(record, filter) {
  return Object.entries(filter).every(([key, cond]) => {
    const val = record[key];
    if (cond && typeof cond === 'object') {       // attacker-controlled operators
      if ('$ne' in cond)     return val !== cond.$ne;
      if ('$gt' in cond)     return val > cond.$gt;
      if ('$lt' in cond)     return val < cond.$lt;
      if ('$in' in cond)     return cond.$in.includes(val);
      if ('$regex' in cond)  return new RegExp(cond.$regex, 'i').test(String(val));
    }
    return val === cond;
  });
}

/** VULNERABLE: passes the attacker filter straight into the matcher */
function matchUser(filter) {
  return users.find((u) => matches(u, filter));
}

module.exports = { searchProducts, getAllProducts, matchUser };