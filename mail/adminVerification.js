const nodemailer = require("nodemailer");

const adminVerification = async (email, name, code, subject) => {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  try {
    const info = await transporter.sendMail({
      from: `Swipe 4 Jobs <${process.env.EMAIL}>`,
      to: email,
      subject: subject,
      text: "Verification code",
      html: `
       <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OTP Verification</title>
            <style>
                body {
                    font-family: 'Arial', sans-serif;
                    background-color: #e9ecef;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    width: 100%;
                    max-width: 600px;
                    margin: 20px auto;
                    background: #ffffff;
                    border-radius: 10px;
                    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                }
                .header {
                    background: #007bff;
                    color: #ffffff;
                    text-align: center;
                    padding: 30px 20px;
                }
                .content {
                    padding: 30px;
                    text-align: center;
                }
                h2 {
                    color: #333;
                }
                .otp {
                    font-size: 28px;
                    font-weight: bold;
                    color: #ff5722;
                    background: #f9f9f9;
                    border: 2px dashed #ff5722;
                    display: inline-block;
                    padding: 10px 20px;
                    border-radius: 5px;
                    margin: 20px 0;
                }
                .footer {
                    text-align: center;
                    font-size: 14px;
                    color: #666;
                    padding: 20px;
                    background: #f1f1f1;
                }
                .button {
                    display: inline-block;
                    background: #007bff;
                    color: #ffffff;
                    padding: 12px 20px;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    transition: background 0.3s;
                }
                .button:hover {
                    background: #0056b3;
                }
                @media (max-width: 600px) {
                    .container {
                        padding: 15px;
                    }
                    .header {
                        padding: 20px;
                    }
                    .content {
                        padding: 20px;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to Swap 4 Jobs</h1>
                </div>
                <div class="content">
                    <h2>OTP Verification</h2>
                    <p>Hi ${name}!</p>
                    <p>Your One-Time Password (OTP) for logging into your admin account is:</p>
                    <div class="otp">${code}</div>
                    <p>This OTP is valid for 10 minutes. Please enter it to access your dashboard.</p>
                    <a href=${process.env.FRONTEND_URL} class="button">Visit website</a>
                </div>
                <div class="footer">
                    <p>&copy; 2024 Swap 4 Jobs. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>

        `,
    });
  } catch (error) {
    console.error("Error sending email:", error);
  }
};

module.exports = adminVerification;
