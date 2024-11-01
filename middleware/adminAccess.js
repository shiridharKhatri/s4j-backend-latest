const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET_ADMIN;
const adminAccess = async (req, res, next) => {
  const token = await req.header("auth-token");
  try {
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "You dont have access to take any action",
      });
    }
    let data = jwt.verify(token, JWT_SECRET);
    req.admin = data.admin;
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
  next();
};

module.exports = adminAccess
