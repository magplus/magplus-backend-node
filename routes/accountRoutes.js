const express = require('express');
const accountController = require('../controllers/accountsController');
const router = express.Router();

router.get('/', accountController.index);
router.get('/new', accountController.new);
router.post('/create', accountController.create);
router.post('/add-subscription', accountController.addSubscription); // Add this line
router.get('/:id/edit', accountController.edit);
router.put('/:id', accountController.update);

module.exports = router;
