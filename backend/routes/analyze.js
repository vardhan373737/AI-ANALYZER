const express = require('express');
const multer = require('multer');
const {
	analyze,
	listReports,
	scanUrl,
	uploadAndAnalyze,
	deleteReport
} = require('../controllers/analyzeController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post('/', authMiddleware, analyze);
router.post('/url', authMiddleware, scanUrl);
router.post('/upload', authMiddleware, upload.single('file'), uploadAndAnalyze);
router.get('/reports', authMiddleware, listReports);
router.delete('/reports/:id', authMiddleware, deleteReport);

module.exports = router;
