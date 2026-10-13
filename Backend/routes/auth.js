
const express = require("express");
const router = express.Router();
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const db = require("../db");

// Gmail email transporter
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: true,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

// Enrollment number format validation
function validateEnrollment(enrollmentNumber) {
    return /^0192[A-Z]{2}\d{2}\d{4}$/.test(enrollmentNumber);
}

// Validate enrollment API
router.post("/validate-enrollment", (req, res) => {
    const { enrollmentNumber } = req.body;

    if (typeof enrollmentNumber !== "string" ||
        !validateEnrollment(enrollmentNumber.trim().toUpperCase())) {
        return res.status(400).json({
            success: false,
            message: "Invalid enrollment number format"
        });
    }

    res.json({
        success: true,
        message: "Enrollment number format is valid"
    });
});

// Generate, save and email OTP
router.post("/send-otp", async (req, res) => {
    try {
        const { email, enrollmentNumber } = req.body;

        if (typeof email !== "string" ||
            typeof enrollmentNumber !== "string" ||
            !email.trim() || !enrollmentNumber.trim()) {
            return res.status(400).json({
                success: false,
                message: "Email and enrollment number are required"
            });
        }

        const normalizedEmail = email.trim().toLowerCase();
        const normalizedEnrollment =
            enrollmentNumber.trim().toUpperCase();

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
            return res.status(400).json({
                success: false,
                message: "Please enter a valid email address"
            });
        }

        if (!validateEnrollment(normalizedEnrollment)) {
            return res.status(400).json({
                success: false,
                message: "Invalid enrollment number format"
            });
        }

        // Check for an existing account
        db.query(
            `SELECT id FROM users
             WHERE email = ? OR college_id = ?
             LIMIT 1`,
            [normalizedEmail, normalizedEnrollment],
            async (err, results) => {
                if (err) {
                    console.error("User lookup failed:", err.message);
                    return res.status(500).json({
                        success: false,
                        message: "Database error"
                    });
                }

                if (results.length > 0) {
                    return res.status(409).json({
                        success: false,
                        message: "Email or enrollment number is already registered"
                    });
                }

                try {
                    const otp = crypto
                        .randomInt(100000, 1000000)
                        .toString();

                    const otpHash = await bcrypt.hash(otp, 10);

                    const expiresAt =
                        new Date(Date.now() + 5 * 60 * 1000);

                    // Save OTP hash before sending email
                    db.query(
                        `INSERT INTO email_otps
                         (email, enrollment_number, otp_hash, expires_at)
                         VALUES (?, ?, ?, ?)`,
                        [
                            normalizedEmail,
                            normalizedEnrollment,
                            otpHash,
                            expiresAt
                        ],
                        async (insertErr) => {
                            if (insertErr) {
                                console.error(
                                    "OTP database insert failed:",
                                    insertErr.message
                                );

                                return res.status(500).json({
                                    success: false,
                                    message: "Could not save OTP"
                                });
                            }

                            try {
                                await transporter.sendMail({
                                    from: process.env.SMTP_USER,
                                    to: normalizedEmail,
                                    subject: "CampusConnect Email Verification OTP",
                                    text: `Your CampusConnect OTP is ${otp}. It expires in 5 minutes. Do not share this code with anyone.`
                                });

                                return res.json({
                                    success: true,
                                    message: "OTP sent to your email successfully"
                                });
                            } catch (emailError) {
                                console.error(
                                    "Email sending failed:",
                                    emailError.message
                                );

                                return res.status(500).json({
                                    success: false,
                                    message: "Email could not be sent. Please check SMTP settings."
                                });
                            }
                        }
                    );
                } catch (error) {
                    console.error("OTP generation failed:", error.message);

                    return res.status(500).json({
                        success: false,
                        message: "Could not generate OTP"
                    });
                }
            }
        );
    } catch (error) {
        console.error("Send OTP error:", error.message);

        return res.status(500).json({
            success: false,
            message: "Something went wrong"
        });
    }
});

module.exports = router;
