const { createAccount, createAnnouncement } = require('../models/accounts');
const { findOrCreateUser } = require('../models/user');
const pool = require('../db'); 

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

      const user = await findOrCreateUser(req.body.user);

      const accountData = {
          account_type: req.body.account.account_type, 
          user_id: user.id,
          billing_attention: req.body.account.billing_attention,
          billing_address: req.body.account.billing_address,
          billing_city: req.body.account.billing_city,
          billing_country: req.body.account.billing_country,
          billing_email_address: req.body.account.billing_email_address, 
      };
      
      const account = await createAccount(accountData); 

      const announcementData = {
          body: req.body.announcement.body, 
          account_id: account.id,
          
      };
      const announcement = await createAnnouncement(announcementData);

      await client.query('COMMIT');

      return res.status(201).json({
          message: 'Account, Announcement created successfully',
          account,
          announcement,
      });
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
