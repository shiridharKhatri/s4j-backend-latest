const nodemailer = require("nodemailer");

const postRejectionMessage = async (email, name, subject, message, jobData) => {
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
      text: "Your Submission Has Been Rejected",
      html: `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Job Posting Rejection Notification</title>
                <style>
                    body { 
                        background: #f7fafc; 
                        font-family: Arial, sans-serif; 
                        margin: 0; 
                        padding: 20px; 
                    }
                    .container { 
                        max-width: 600px; 
                        margin: auto; 
                        background: white; 
                        padding: 20px; 
                        border-radius: 10px; 
                        box-shadow: 0 4px 10px rgba(0,0,0,0.2); 
                    }
                    h1 { 
                        color: #ffffff; 
                        font-size: 17px; 
                        text-align: center; 
                        padding: 20px;
                        background: linear-gradient(to right, #e53e3e, #fc8181); 
                        -webkit-background-clip: text; 
                        -webkit-text-fill-color: transparent; 
                        margin-bottom: 10px; 
                    }
                    h2 { 
                        color: #2d3748; 
                        font-size: 22px; 
                        margin-top: 15px; 
                    }
                    p { 
                        color: #4a5568; 
                        line-height: 1.6; 
                    }
                    .card { 
                        padding: 20px; 
                        border-radius: 8px; 
                        margin-top: 10px; 
                        background: #edf2f7; 
                        border: 1px solid #cbd5e0; 
                    }
                    .error { 
                        background: #fff5f5; 
                        border: 1px solid #fed7e2; 
                    }
                    .button { 
                        display: inline-block; 
                        padding: 10px 15px; 
                        background: linear-gradient(to right, #e53e3e, #fc8181); 
                        color: white; 
                        text-decoration: none; 
                        border-radius: 5px; 
                        text-align: center; 
                        font-weight: bold; 
                        margin-top: 20px; 
                    }
                    .button:hover { 
                        background: linear-gradient(to right, #c53030, #f56565); 
                    }
                    footer { 
                        text-align: center; 
                        margin-top: 30px; 
                        font-size: 14px; 
                        color: #718096; 
                    }
                    footer a {
                    color: #ffffff;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Job Posting Rejected</h1>
                    <p>Hi ${name},</p>
                    <p>Thank you for submitting your job listing on Swipe 4 Jobs. Unfortunately, your job posting has been rejected.</p>

                    <div class="card">
                        <h2>Job Details</h2>
                        <p><strong>Job Title:</strong> ${jobData.name}</p>
                        <p><strong>Location:</strong> ${jobData.location}</p>
                        <p><strong>Posted On:</strong> ${jobData.date}</p>
                    </div>

                    <div class="card error">
                        <h2>Reason for Rejection</h2>
                        <p>${message}</p>
                    </div>

                    <p>If you have any questions or would like to discuss this further, please reach out to our support team.</p>
                    
                    <footer>
                        <p>Best Regards,<br>The Swipe 4 Jobs Team</p>
                        <a href=${process.env.FRONTEND_URL} class="button">Visit Our Website</a>
                    </footer>
                </div>
            </body>
            </html>
`,
    });
  } catch (error) {
    console.error("Error sending email:", error);
  }
};

module.exports = postRejectionMessage;
