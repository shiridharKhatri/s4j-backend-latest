const JWT_SECRET_USER = process.env.JWT_SECRET_USER;
const jwt = require("jsonwebtoken");
const userAccess = async (req, res, next) => {
  try {
    const token = await req.header("auth-token");
    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: "Please enter valid token" });
    }
    let data = jwt.verify(token, JWT_SECRET_USER);
    req.user = data.user;
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
  next();
};
module.exports = userAccess;
