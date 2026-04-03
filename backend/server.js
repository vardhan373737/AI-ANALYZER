const path = require('path');
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const dotenv = require('dotenv');

// Load environment variables, checking for .env.local first (for development)
const envFile = process.env.NODE_ENV === 'production' ? '.env' : '.env.local';
dotenv.config({ path: path.join(__dirname, '..', envFile) });

const authRoutes = require('./routes/auth');
const analyzeRoutes = require('./routes/analyze');

const app = express();
const port = process.env.PORT || 5000;
const frontendPath = path.join(__dirname, '..', 'frontend');

app.use(cors({ origin: process.env.CLIENT_URL || true }));
app.use(express.json());
app.use(
  morgan('dev', {
    skip: (req) => !req.originalUrl.startsWith('/api/')
  })
);
app.use(express.static(frontendPath));

app.get('/', (req, res) => {
  res.sendFile(path.join(frontendPath, 'index.html'));
});

app.use('/api/auth', authRoutes);
app.use('/api/analyze', analyzeRoutes);

app.use((req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`AI Cyber Analyzer running on http://localhost:${port}`);
  });
}

module.exports = app;
