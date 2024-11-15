const express = require("express");
const User = require("../models/User");
const routes = express.Router();
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const JWT_SECRET = process.env.JWT_SECRET_USER;
const { body, validationResult } = require("express-validator");
const verificationMail = require("../mail/verification");
const userAccess = require("../middleware/userAccess");
const adminAccess = require("../middleware/adminAccess");
const Admin = require("../models/Admin");
const forgetPassword = require("../mail/forgetPassword");

const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res, next, options) => {
    const rateLimitData = await options.store.increment(req.ip);

    if (rateLimitData && rateLimitData.resetTime) {
      const now = Date.now();
      const retryAfterMs = rateLimitData.resetTime - now;
      const retryAfterMinutes = Math.ceil(retryAfterMs / 1000 / 60);

      res.status(429).json({
        success: false,
        type: "attempts",
        message: `Too many attempts. Please try again after ${retryAfterMinutes} minute(s).`,
      });
    } else {
      res.status(429).json({
        success: false,
        type: "attempts",
        message: "Too many attempts. Please try again later.",
      });
    }
  },
});

const generateCodeNumber = () => {
  return Math.floor(100000 + Math.random() * 900000);
};

routes.post(
  "/auth/signup",
  [
    body("name", "Name must be at least 2 characters long.").isLength({
      min: 2,
    }),
    body("email", "Please provide a valid email address.").isEmail(),
    body(
      "password",
      "Password must be at least 6 characters long, with at least one uppercase letter and one special character."
    ).isStrongPassword(),
  ],
  async (req, res) => {
    const error = validationResult(req);
    if (!error.isEmpty()) {
      return res.status(400).json({ success: false, message: error.array() });
    }
    try {
      let verificationCode = generateCodeNumber();
      const { name, email, password } = req.body;
      let user = await User.findOne({ email });
      if (user) {
        return res.status(401).json({
          success: false,
          type: "email",
          message: "User with this email already exist",
        });
      }
      let salt = await bcrypt.genSalt(10);
      let hashedPassword = await bcrypt.hash(password, salt);
      let newUser = await User.create({
        name,
        email,
        verificationCode: verificationCode,
        password: hashedPassword,
      });
      verificationMail(
        email,
        name,
        verificationCode,
        "Email verification code"
      );

      return res.status(200).json({
        success: true,
        id: newUser._id,
        message:
          "User created successfully! Verify your account to start using it.",
      });
    } catch (error) {
      return res
        .status(500)
        .json({ success: false, type: "server", message: error.message });
    }
  }
);
routes.post(
  "/auth/login",
  loginLimiter,
  [body("password").exists()],
  async (req, res) => {
    try {
      let verificationCode = generateCodeNumber();
      const { email, password } = req.body;
      let user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({
          success: false,
          type: "user",
          message: "User not found with given detail",
        });
      }

      const validatePassword = await bcrypt.compare(password, user.password);
      if (!validatePassword) {
        return res.status(401).json({
          success: false,
          message: "Email or Password field is incorrect",
        });
      }
      if (user.isVerified === false) {
        verificationMail(
          user.email,
          user.name,
          verificationCode,
          "Email verification code",
          "It looks like you're not verified yet. Please copy the six-digit verification code below to complete the process and access our service."
        );
        await User.findByIdAndUpdate(
          user._id,
          { $set: { verificationCode } },
          { new: true }
        );
        return res.status(403).json({
          success: false,
          type: "verification",
          id: String(user._id),
          message: "Account unverified ! Please verify your account to use",
        });
      }
      let data = {
        user: {
          id: user.id,
        },
      };
      let token = jwt.sign(data, JWT_SECRET, { expiresIn: "168h" });
      return res.status(200).json({ success: true, token, id: user._id });
    } catch (error) {
      return res
        .status(500)
        .json({ success: false, type: "server", message: error.message });
    }
  }
);

routes.post("/auth/verification/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { code } = req.body;
    let user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        success: false,
        type: "id",
        message: "User not found with given id",
      });
    }
    if (user.isVerified === true) {
      return res.status(409).json({
        success: false,
        type: "verified",
        message: "User is already verified",
      });
    }
    if (Number(user.verificationCode) !== Number(code)) {
      return res.status(403).json({
        success: false,
        type: "code",
        message: "Incorrect code! Please recheck and try again",
      });
    }
    await User.findByIdAndUpdate(
      id,
      { $set: { isVerified: true, verificationCode: null } },
      { new: true }
    );
    return res
      .status(200)
      .json({ success: true, message: "User verified successfully!" });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, type: "server", message: error.message });
  }
});

routes.get("/auth/verification/fetch", userAccess, async (req, res) => {
  try {
    let user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found with given id" });
    }
    return res.status(200).json({ success: true, user });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, type: "server", message: error.message });
  }
});

routes.get("/auth/user/fetch", adminAccess, async (req, res) => {
  try {
    let admin = await Admin.findById(req.admin.id);
    if (!admin) {
      return res
        .status(401)
        .json({ succes: false, message: "You can't access this end point" });
    }
    let users = await User.find().select("-password");
    if (!users) {
      return res
        .status(404)
        .json({ success: false, message: "No registered users found!" });
    }
    return res.status(200).json({ success: true, total: users.length, users });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, type: "server", message: error.message });
  }
});

routes.delete(
  "/auth/user/remove/admin/:userId",
  adminAccess,
  async (req, res) => {
    try {
      const { userId } = req.params;
      let user = await User.findById(userId);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found with given id" });
      }
      await User.findByIdAndDelete(userId);
      return res.status(200).json({
        success: true,
        message: `${user.name} got removed successfully`,
      });
    } catch (error) {
      return res
        .status(500)
        .json({ success: false, type: "server", message: error.message });
    }
  }
);

routes.delete("/auth/user/remove/:userId", userAccess, async (req, res) => {
  try {
    const { userId } = req.params;
    if (String(userId) !== String(req.user.id)) {
      return res.status(401).json({
        success: false,
        message: "You don't have access to take action",
      });
    }
    let user = await User.findById(userId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "No user found with given id" });
    }
    await User.findByIdAndDelete(userId);
    return res
      .status(200)
      .json({ success: true, message: "Account deleted successfully!" });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, type: "server", message: error.message });
  }
});

routes.post("/auth/change/password/:id", userAccess, async (req, res) => {
  try {
    const { id } = req.params;
    const { password, newPassword } = req.body;
    if (String(id) !== String(req.user.id)) {
      return res.status(401).json({
        success: false,
        type: "unauthorized",
        message: "You dont access to change password",
      });
    }
    let user = await User.findById(id);
    if (!user) {
      return res.status(404).json({
        succes: false,
        type: "notfound",
        message: "User not found with given id",
      });
    }

    if (!user.password) {
      return res.status(500).json({
        success: false,
        type: "server",
        message: "User password is not set in the database.",
      });
    }

    let comparePassword = await bcrypt.compare(password, user.password);
    if (!comparePassword) {
      return res.status(401).json({
        success: false,
        type: "password",
        message: "The entered password does not match the current password.",
      });
    }

    let salt = await bcrypt.genSalt(10);
    let hashedPassword = await bcrypt.hash(newPassword, salt);
    await User.findByIdAndUpdate(
      id,
      { $set: { password: hashedPassword } },
      { new: true }
    );

    return res.status(200).json({
      success: true,
      message: "Password has been changed successfully",
    });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, type: "server", message: error.message });
  }
});

routes.post("/auth/forget/password", async (req, res) => {
  try {
    const { email } = req.body;
    let code = generateCodeNumber();
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found with given email address",
      });
    }

    let url = `${process.env.FRONTEND_URL}/user/forget/password/${email}/${code}`;
    forgetPassword(user.email, user.name, "Forget password verification", url);

    await User.findByIdAndUpdate(user._id, {
      $set: { verificationCode: code, isVerified: false },
    });
    res.status(200).json({
      success: true,
      message: "Please check your email to change password",
    });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, type: "server", message: error.message });
  }
});

routes.post("/auth/forget/password/verify/:code/:email", async (req, res) => {
  try {
    const { code, email } = req.params;
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found with given email address",
      });
    }
    if (Number(user.verificationCode) !== Number(code)) {
      return res.status(401).json({
        success: false,
        message: "The code may not be valid, as it might have already expired.",
      });
    }
    res.status(200).json({
      succes: true,
      message: "The code has been successfully validated.",
    });
  } catch (error) {
    return res.status(500).json({ succes: false, message: error.message });
  }
});

routes.post("/auth/code/verification", async (req, res) => {
  try {
    let { email, code } = req.body;
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found with given email address",
      });
    } else if (Number(user.verificationCode) !== Number(code)) {
      return res.status(403).json({
        success: false,
        message:
          "The link may have expired. Please try using the Forgot Password option again.",
      });
    }
    res.status(200).json({
      succes: true,
      message: "Verification successful enter your new password",
    });
  } catch (error) {
    return res.status(500).json({ succes: false, message: error.message });
  }
});

routes.post("/auth/reset/password", async (req, res) => {
  try {
    let { email, code, password } = req.body;
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "No user found with the provided email address.",
      });
    }
    if (user && Number(user.verificationCode) !== Number(code)) {
      return res.status(401).json({
        success: false,
        message:
          "The verification code is incorrect. Password reset cannot be completed.",
      });
    }
    let salt = await bcrypt.genSalt(10);
    let hashedPas = await bcrypt.hash(password, salt);
    await User.findByIdAndUpdate(
      user._id,
      {
        $set: { verificationCode: null, isVerified: true, password: hashedPas },
      },
      { new: true }
    );
    res.status(200).json({
      success: true,
      message: "Your password has been successfully reset.",
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = routes;
