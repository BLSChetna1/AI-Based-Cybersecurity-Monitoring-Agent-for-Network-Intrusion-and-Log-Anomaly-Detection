
const express = require("express");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// Import log analysis routes
const logsRouter = require("./routes/logs");

// Home route
app.get("/", (req, res) => {
  res.json({
    message: "AI-Based Cybersecurity Monitoring Backend is running!",
    status: "success"
  });
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "OK",
    message: "Backend server is healthy"
  });
});

// Log analysis API
app.use("/api", logsRouter);

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
