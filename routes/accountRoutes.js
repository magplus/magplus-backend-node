const express = require('express');
const accountController = require('../controllers/accountsController');
const router = express.Router();

router.get('/', accountController.index);
router.get('/new', accountController.new);
router.post('/create', accountController.create);
router.get('/:id/edit', accountController.edit);
router.put('/:id', accountController.update);

module.exports = router;
