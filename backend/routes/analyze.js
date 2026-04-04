const express = require('express');
const multer = require('multer');
const {
	analyze,
	listReports,
	scanUrl,
	uploadAndAnalyze,
	deleteReport,
	exportReportPdf,
	getPdfExportConfig
} = require('../controllers/analyzeController');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post('/', authMiddleware, analyze);
router.post('/url', authMiddleware, scanUrl);
router.post('/upload', authMiddleware, upload.single('file'), uploadAndAnalyze);
router.get('/reports', authMiddleware, listReports);
router.get('/pdf-config', authMiddleware, getPdfExportConfig);
router.get('/reports/:id/pdf', authMiddleware, exportReportPdf);
router.delete('/reports/:id', authMiddleware, deleteReport);

module.exports = router;
