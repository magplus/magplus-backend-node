const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'my_publish',
  password: 'postgres',
  port: 5432,
});

const findOrCreateUser = async (userData) => {
  const { email, first_name, name, company, phone } = userData;
  
  let user = await findUserByEmail(email);
  
  if (!user) {
    const password = bcrypt.hashSync('default_password', 10);
    const query = `
      INSERT INTO users (email, first_name, name, company, phone, password)
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;
    `;
    const values = [email, first_name, name, company, phone, password];
    const result = await pool.query(query, values);
    user = result.rows[0];
  }
  
  return user;
};

const findUserByEmail = async (email) => {
  const query = `SELECT * FROM users WHERE email = $1`;
  const result = await pool.query(query, [email]);
  return result.rows[0];
};

module.exports = { findOrCreateUser };
