const nodemailer = require("nodemailer");

const forgetPassword = async (email, name, subject, url) => {
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
    await transporter.sendMail({
      from: `Swipe 4 Jobs <${process.env.EMAIL}>`,
      to: email,
      subject: subject,
      text: "Change passowrd",
      html: `
      <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Your Password</title>
            <style>
                body {
                    font-family: 'Arial', sans-serif;
                    background-color: #f9f9f9;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    max-width: 600px;
                    margin: auto;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 2px 15px rgba(0, 0, 0, 0.1);
                    overflow: hidden;
                }
                .header {
                    background-color: #4A90E2;
                    padding: 30px;
                    text-align: center;
                    color: white;
                }
                .content {
                    padding: 30px;
                }
                h1 {
                    color: #333;
                    margin-bottom: 10px;
                    font-size: 24px;
                }
                p {
                    font-size: 16px;
                    line-height: 1.6;
                    color: #555;
                }
                .btn {
                    display: inline-block;
                    padding: 12px 25px;
                    background-color: #4CAF50;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    transition: background 0.3s ease;
                    text-align: center;
                    margin-top: 20px;
                }
                .btn:hover {
                    background-color: #45a049;
                }

            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Swap 4 Jobs</h1>
                </div>
                <div class="content">
                    <h1>Reset Your Password</h1>
                    <p>Hi ${name},</p>
                    <p>We received a request to reset your password for your Swap 4 Jobs account. If you didn't make this request, you can ignore this email.</p>
                    <a href=${url} class="btn">Change Password</a>
                    <p>Thank you for being a part of the Swap 4 Jobs community!</p>
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

module.exports = forgetPassword;
