const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema(
  {
    userId: { type: String, required: true },
    title: { type: String, required: true },
    summary: { type: String, required: true },
    findings: [
      {
        title: String,
        count: Number,
        severity: String
      }
    ],
    recommendations: [String]
  },
  { timestamps: true }
);

module.exports = mongoose.model('Report', reportSchema);
