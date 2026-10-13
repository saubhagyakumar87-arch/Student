const express = require("express");
const cors = require("cors");
require("dotenv").config();
const db = require("./db");

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

const authRoutes = require("./routes/auth");
app.use("/api/auth", authRoutes);

// Test route
app.get("/", (req, res) => {
    res.send("CampusConnect Backend is Running!");
});

// Server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`CampusConnect server running on port ${PORT}`);
});