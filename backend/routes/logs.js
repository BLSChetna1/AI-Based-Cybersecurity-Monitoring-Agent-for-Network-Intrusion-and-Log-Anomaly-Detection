
const express = require("express");

const router = express.Router();

// Analyze sample security logs
router.post("/analyze-logs", (req, res) => {
  const { logs } = req.body;

  if (!Array.isArray(logs) || logs.length === 0) {
    return res.status(400).json({
      error: "Please provide a non-empty logs array"
    });
  }

  const suspiciousPatterns = [
    {
      name: "Failed login attempt",
      pattern: /failed password|login failed|authentication failure/i
    },
    {
      name: "Possible SQL injection",
      pattern: /union\s+select|sql injection|or\s+1\s*=\s*1/i
    },
    {
      name: "Possible port scanning",
      pattern: /port scan|port scanning/i
    },
    {
      name: "Possible unauthorized access",
      pattern: /unauthorized access|access denied/i
    }
  ];

  const results = logs.map((log) => {
    const message = String(log);

    const matches = suspiciousPatterns
      .filter((item) => item.pattern.test(message))
      .map((item) => item.name);

    return {
      log: message,
      suspicious: matches.length > 0,
      alerts: matches
    };
  });

  const suspiciousCount = results.filter(
    (item) => item.suspicious
  ).length;

  res.json({
    totalLogs: results.length,
    suspiciousCount,
    safeCount: results.length - suspiciousCount,
    results
  });
});

module.exports = router;
