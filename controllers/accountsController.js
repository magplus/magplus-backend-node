const { createAccount, createAnnouncement,createSubscription } = require('../models/accounts');
const { findOrCreateUser } = require('../models/user');
const pool = require('../config/db'); 

exports.index = async (req, res) => {
    try {
        const accounts = await getAllAccounts(); 
        return res.status(200).json(accounts);
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Server error' });
    }
};

exports.new = (req, res) => {
    return res.status(200).json({ message: 'Render new account form' });
};

exports.create = async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const userData = req.body.user; 
        if (!userData || !userData.email) {
            return res.status(400).json({ message: 'User  data is required and must include an email' });
        }

        const user = await findOrCreateUser (userData);
        
        const accountData = {
            account_type: req.body.account.account_type,
            name: req.body.account.name,
            billing_attention: req.body.account.billing_attention,
            billing_address: req.body.account.billing_address,
            billing_postal_code: req.body.account.billing_postal_code, 
            billing_city: req.body.account.billing_city,
            billing_country: req.body.account.billing_country,
            us_states: req.body.account.us_states, 
            other_states: req.body.account.other_states, 
            billing_email_address: req.body.account.billing_email_address,
            currency: req.body.account.currency, 
            vat: req.body.account.vat, 
            pay_by_invoice: req.body.account.pay_by_invoice, 
            account_region: req.body.account.account_region, 
            key_account_manager_id: req.body.account.key_account_manager_id, 
            comments: req.body.account.comments, 
            account_active: req.body.account.account_active, 
            user_id: user.id 
        };

        const newAccount = await createAccount(accountData); 

        // Handle subscriptions
        const subscriptions = req.body.subscriptions; // Assuming subscriptions are sent in the request body
if (subscriptions && Array.isArray(subscriptions)) {
    for (const product_name of subscriptions) {
        await createSubscription({ product_name, account_id: newAccount.id });
    }
}

        await client.query('COMMIT');
        return res.status(201).json({ message: 'Account created successfully!', account: newAccount });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error(error);
        return res.status(500).json({ message: 'Server error' });
    } finally {

        client.release();
    }
};


exports.edit = async (req, res) => {
    try {
        const accountId = req.params.id;
        const account = await getAccountById(accountId); 
        return res.status(200).json(account);
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Server error' });
    }
};

exports.update = async (req, res) => {
    const accountId = req.params.id;
    try {
        const updatedAccount = await updateAccount(accountId, req.body.account); 
        return res.status(200).json({ message: 'Account updated successfully', updatedAccount });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Server error' });
    }
};
exports.addSubscription = async (req, res) => {
    const { product_name, account_id } = req.body;

    if (!product_name || !account_id) {
        return res.status(400).json({ message: 'Product name and account ID are required.' });
    }

    try {
        const newSubscription = await createSubscription({ product_name, account_id });
        return res.status(201).json({ message: 'Subscription added successfully!', subscription: newSubscription });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'Server error' });
    }
};