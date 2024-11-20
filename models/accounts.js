const { Pool } = require('pg');
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'my_publish',
    password: 'postgres',
    port: 5432,
    ssl: false
});

const createAccount = async (accountData) => {
    const { account_type, user_id, billing_attention, billing_address, billing_city, billing_country, billing_email_address } = accountData; 
  
    const query = `
      INSERT INTO accounts (account_type, user_id, billing_attention, billing_address, billing_city, billing_country, billing_email_address)
      VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;
    `;
    
    const values = [account_type, user_id, billing_attention, billing_address, billing_city, billing_country, billing_email_address];
    const result = await pool.query(query, values);
    return result.rows[0];
};


const createAnnouncement = async (announcementData) => {
    const { body, account_id, billing_attention, billing_address, billing_city, billing_country, billing_email_address } = announcementData;

    const query = `
      INSERT INTO announcements (body, billing_attention, billing_address, billing_city, billing_country, billing_email_address, account_id)
      VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;  -- Keep billing fields in the announcements table
    `;

    const values = [body, billing_attention, billing_address, billing_city, billing_country, billing_email_address, account_id];
    const result = await pool.query(query, values);
    return result.rows[0];
};
const createSubscription = async (subscriptionData) => {
  const { product_name, account_id } = subscriptionData; 
  const createdAt = new Date(); 
  const updatedAt = new Date(); 

  const query = `
      INSERT INTO magplus_subscriptions (product_name, account_id, created_at, updated_at)
      VALUES ($1, $2, $3, $4) RETURNING *;
  `;
  
  const values = [product_name, account_id, createdAt, updatedAt];
  const result = await pool.query(query, values);
  return result.rows[0];
};

module.exports = { createAccount, createAnnouncement, createSubscription };

// Function to insert data into key_account_managers table
// const createKeyAccountManager = async (managerData) => {
//     const { manager_name, manager_email, account_id } = managerData;
    
//     const query = `
//       INSERT INTO key_account_managers (manager_name, manager_email, account_id)
//       VALUES ($1, $2, $3) RETURNING *;
//     `;
    
//     const values = [manager_name, manager_email, account_id];
//     const result = await pool.query(query, values);
//     return result.rows[0];
// };

// module.exports = { createAccount, createAnnouncement };
