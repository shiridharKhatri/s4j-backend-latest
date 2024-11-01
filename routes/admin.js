const Admin = require("../models/Admin");
const express = require("express");
const routes = express.Router();
const { body, validationResult } = require("express-validator");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const adminAccess = require("../middleware/adminAccess");
const adminVerification = require("../mail/adminVerification");
const secret = process.env.JWT_SECRET_ADMIN;

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

const codeGenerator = () => {
  return Math.floor(100000 + Math.random() * 900000);
};

const genericErrorResponse = {
  success: false,
  message: "Invalid email or password.",
};

routes.post(
  "/admin/new/create",
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
  adminAccess,
  async (req, res) => {
    const error = validationResult(req);
    if (!error.isEmpty()) {
      return res.status(400).json({ success: false, error });
    }

    try {
      const { name, email, password, role } = req.body;
      const existingAdmin = await Admin.findOne({ email });
      // const admin = await Admin.findById(req.admin.id);
      if (existingAdmin) {
        return res.status(409).json({
          success: false,
          type: "email",
          message:
            "An administrator with this email address already exists. Please try logging in.",
        });
      }
      // if (admin.role !== "admin") {
      //   return res.status(401).json({
      //     success: false,
      //     message: "You dont have access to add new members",
      //   });
      // }
      const salt = await bcryptjs.genSalt(10);
      const hashedPassword = await bcryptjs.hash(password, salt);

      await Admin.create({
        name,
        email,
        password: hashedPassword,
        role,
      });

      return res
        .status(200)
        .json({ success: true, message: "Admin created successfully!" });
    } catch (error) {
      return res.status(500).json({ success: false, message: error.message });
    }
  }
);

routes.post("/admin/existing/access", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });

    if (!admin) {
      return res.status(400).json(genericErrorResponse);
    }

    const validPassword = await bcryptjs.compare(password, admin.password);
    if (!validPassword) {
      return res.status(400).json(genericErrorResponse);
    }

    const verificationCode = codeGenerator();
    adminVerification(
      email,
      admin.name,
      verificationCode,
      "Admin verification code"
    );
    await Admin.findByIdAndUpdate(admin.id, {
      $set: { verificationCode, isVerified: false },
    });

    return res.status(200).json({
      success: true,
      id: admin.id,
      message: "Verify your email to access the admin dashboard.",
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

routes.post(
  "/admin/existing/access/verification/:id",
  loginLimiter,
  async (req, res) => {
    try {
      const id = req.params.id;
      const { code } = req.body;

      const admin = await Admin.findById(id).select("-password");

      if (!admin) {
        return res
          .status(404)
          .json({ success: false, message: "Admin not found." });
      }

      if (String(code).length !== 6 || admin.verificationCode !== code) {
        return res.status(400).json({
          success: false,
          message: "Invalid verification code.",
        });
      }

      await Admin.findByIdAndUpdate(id, {
        $set: { verificationCode: null, isVerified: true },
      });

      const data = {
        admin: {
          id: admin.id,
        },
      };
      const token = jwt.sign(data, secret, { expiresIn: "168h" });

      return res.status(200).json({
        success: true,
        message: "Admin verified successfully.",
        token,
      });
    } catch (error) {
      return res.status(500).json({ success: false, message: error.message });
    }
  }
);

routes.post("/admin/existing/access/fetch/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const admin = await Admin.findById(id).select("-password");

    if (!admin) {
      return res
        .status(404)
        .json({ success: false, message: "Admin not found!" });
    }

    return res
      .status(200)
      .json({ success: true, id: admin.id, email: admin.email });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

routes.post(
  "/admin/existing/access/fetch-all",
  adminAccess,
  async (req, res) => {
    try {
      let admin = await Admin.findById(req.admin.id).select("-password");
      if (!admin) {
        return res
          .status(404)
          .json({ success: false, message: "Cannot access admin details" });
      } else {
        const adminData = await Admin.find().select("-password");
        return res.status(200).json({ success: true, adminData });
      }
    } catch (error) {
      return res.status(500).json({ success: false, message: error.message });
    }
  }
);
routes.post(
  "/admin/existing/access/change-role/:id/:role",
  adminAccess,
  async (req, res) => {
    try {
      let admin = await Admin.findById(req.admin.id);
      if (String(admin._id) === req.params.id) {
        return res.status(401).json({
          success: false,
          message: "You cannot modify your own role.",
        });
      } else {
        if (admin.role !== "admin") {
          return res.status(401).json({
            success: false,
            message: "You do not have permission to modify.",
          });
        } else {
          let searchAdmin = await Admin.findById(req.params.id);
          if (!searchAdmin) {
            return res.status(404).json({
              success: false,
              message: "Admin not found with given id",
            });
          } else {
            await Admin.findByIdAndUpdate(
              req.params.id,
              { $set: { role: req.params.role } },
              { new: true }
            );
            return res
              .status(200)
              .json({ success: true, message: "Role has been changed!" });
          }
        }
      }
    } catch (error) {
      return res.status(500).json({ success: false, message: error.message });
    }
  }
);

routes.delete("/admin/existing/delete/:id", adminAccess, async (req, res) => {
  try {
    const { id } = req.params;
    let admin = await Admin.findById(req.admin.id);
    let filterAdmin = await Admin.findById(id);
    if (!filterAdmin) {
      return res
        .status(404)
        .json({ success: false, message: "Admin not found with given id" });
    } else {
      if (String(admin._id) === String(filterAdmin.id)) {
        await Admin.findByIdAndDelete(id);
        return res
          .status(200)
          .json({ success: true, message: "Admin deleted successfullly!" });
      } else {
        if (admin.isVerified === true && admin.role === "admin") {
          await Admin.findByIdAndDelete(id);
          res.status(200).json({
            success: true,
            message: `${filterAdmin.name} got deleted successfully`,
          });
        } else {
          res.status(401).json({
            success: false,
            message: "Only admin can take such action",
          });
        }
      }
    }
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

routes.get("/admin/existing/fetch", adminAccess, async (req, res) => {
  try {
    let admin = await Admin.findById(req.admin.id).select("-password");
    if (!admin) {
      return res
        .status(404)
        .json({ success: false, message: "Admin not found!" });
    } else {
      return res.status(200).json({ success: true, admin });
    }
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});
module.exports = routes;
