
const express = require("express");

const router = express.Router();

// Security log patterns and severity levels
const suspiciousPatterns = [
  {
    name: "Possible SQL injection",
    pattern: /union\s+select|sql injection|or\s+1\s*=\s*1/i,
    severity: "HIGH"
  },
  {
    name: "Possible port scanning",
    pattern: /port scan|port scanning/i,
    severity: "MEDIUM"
  },
  {
    name: "Failed login attempt",
    pattern: /failed password|login failed|authentication failure/i,
    severity: "MEDIUM"
  },
  {
    name: "Possible unauthorized access",
    pattern: /unauthorized access|access denied/i,
    severity: "HIGH"
  }
];

// Analyze security logs
router.post("/analyze-logs", (req, res) => {
  const { logs } = req.body;

  // Validate input
  if (!Array.isArray(logs) || logs.length === 0) {
    return res.status(400).json({
      error: "Please provide a non-empty logs array"
    });
  }

  // Analyze each log
  const results = logs.map((log) => {
    const message = String(log);

    const matches = suspiciousPatterns.filter(
      (item) => item.pattern.test(message)
    );

    // Determine severity
    const severity = matches.length
      ? matches.some((item) => item.severity === "HIGH")
        ? "HIGH"
        : "MEDIUM"
      : "LOW";

    // Generate security recommendations
    let recommendation;

    if (severity === "HIGH") {
      recommendation =
        "Investigate immediately and review the related security logs.";
    } else if (severity === "MEDIUM") {
      recommendation =
        "Review the activity and check for repeated suspicious attempts.";
    } else {
      recommendation =
        "No immediate action required. Continue monitoring.";
    }

    return {
      log: message,
      suspicious: matches.length > 0,
      severity,
      alerts: matches.map((item) => item.name),
      recommendation
    };
  });

  // Count suspicious and safe logs
  const suspiciousCount = results.filter(
    (item) => item.suspicious
  ).length;

  const safeCount = results.length - suspiciousCount;

  // Summarize severity levels
  const severitySummary = {
    high: results.filter(
      (item) => item.severity === "HIGH"
    ).length,

    medium: results.filter(
      (item) => item.severity === "MEDIUM"
    ).length,

    low: results.filter(
      (item) => item.severity === "LOW"
    ).length
  };

  // Send response
  res.json({
    totalLogs: results.length,
    suspiciousCount,
    safeCount,
    severitySummary,
    results
  });
});

module.exports = router;
