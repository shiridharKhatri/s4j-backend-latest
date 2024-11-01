const express = require("express");
const routes = express.Router();
const multer = require("multer");
const path = require("path");
const moment = require("moment");
const Postjob = require("../models/Postjob");
const fs = require("fs");
const adminAccess = require("../middleware/adminAccess");
const userAccess = require("../middleware/userAccess");
const User = require("../models/User");
const PostConst = require("../models/PostConst");
const postRejectionMessage = require("../mail/postRejection");
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "./images");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = moment()
      .subtract(10, "days")
      .calendar()
      .replaceAll("/", "-");
    cb(
      null,
      file.fieldname +
        "-" +
        uniqueSuffix +
        "-" +
        Math.random() * 10000 +
        "-" +
        file.originalname
    );
  },
});

const fileFilter = (req, file, cb) => {
  const filetypes = /jpeg|jpg|png/;
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = filetypes.test(file.mimetype);

  if (extname && mimetype) {
    cb(null, true);
  } else {
    cb(new Error("File must be a JPG or PNG format!"));
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: fileFilter,
});

// for admin
routes.post("/post-job/admin/:id", adminAccess, (req, res) => {
  if (String(req.admin.id) !== String(req.params.id)) {
    return res
      .status(401)
      .json({ success: false, message: "You're not allowed to post" });
  }
  upload.single("logo")(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ success: false, message: err.message });
    }
    try {
      const { name, schedule, state, code, city, zip, overview, position } =
        req.body;
      const existingPost = await Postjob.findOne({
        name,
        position,
        state,
        city,
        zip,
      });

      if (existingPost) {
        fs.readdir("./images", (err, file) => {
          if (err) {
            console.log("Error reading file ./images");
          } else {
            file.forEach((file) => {
              if (file === req.file.filename) {
                const filePath = path.join("./images", file);
                fs.unlink(filePath, (err) => {
                  if (err) {
                    return;
                  }
                });
              }
            });
          }
        });
        return res.status(409).json({
          success: false,
          message: "Duplicate post: A job with similar details already exists.",
        });
      }

      await Postjob.create({
        postedBy: req.admin.id,
        name,
        schedule,
        state,
        code,
        city,
        zip,
        overview,
        position,
        isApproved: true,
        approvedDate: moment().format("MMMM Do YYYY, h:mm:ss a"),
        logo: req.file,
      });

      return res.status(200).json({
        success: true,
        message: "Post has been successfully sent for review",
      });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  });
});

// for user
routes.post("/post-job/user/:id", userAccess, async (req, res) => {
  // let postConst = await PostConst.find();
  if (String(req.user.id) !== String(req.params.id)) {
    return res
      .status(401)
      .json({ success: false, message: "Please login to post jobs." });
  }
  upload.single("logo")(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ success: false, message: err.message });
    }
    try {
      const { name, schedule, state, code, city, zip, overview, position } =
        req.body;
      const existingPost = await Postjob.findOne({
        name,
        position,
        state,
        city,
        zip,
      });

      if (existingPost) {
        fs.readdir("./images", (err, file) => {
          if (err) {
            console.log("Error reading file ./images");
          } else {
            file.forEach((file) => {
              if (req.file !== undefined) {
                if (file === req.file.filename) {
                  const filePath = path.join("./images", file);
                  fs.unlink(filePath, (err) => {
                    if (err) {
                      return;
                    }
                  });
                }
              }
            });
          }
        });
        return res.status(409).json({
          success: false,
          message: "Duplicate post: A job with similar details already exists.",
        });
      }
      let user = await User.findById(req.user.id);
      let freePostingDate = await PostConst.findById(
        "67133b8ac9b1f8fe80b3ee7c"
      );
      let { start, end } = freePostingDate.free_posting;
      let freeStartDate = new Date(start);
      let freeEndDate = new Date(end);
      let currentDate = new Date();
      if (!(currentDate >= freeStartDate && currentDate <= freeEndDate)) {
        if (user.posting_limit <= 0) {
          return res.status(402).json({
            success: false,
            message: "To post more than one job, a payment is required",
          });
        } else {
          await User.findByIdAndUpdate(
            req.user.id,
            { $set: { posting_limit: user.posting_limit - 1 } },
            { new: true }
          );
        }
      }
      await Postjob.create({
        postedBy: req.user.id,
        name,
        schedule,
        state,
        code,
        city,
        zip,
        overview,
        position,
        logo: req.file,
      });

      return res.status(200).json({
        success: true,
        message: "Post has been successfully sent for review",
      });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  });
});

routes.put("/post-job/edit/:id", adminAccess, async (req, res) => {
  upload.single("logo")(req, res, async (err) => {
    if (err) {
      return res.status(400).json({ success: false, message: err.message });
    }
    try {
      const { name, schedule, state, code, city, zip, overview, position } =
        req.body;
      const { id } = req.params;
      let post = await Postjob.findById(id);
      if (!post) {
        return res
          .status(404)
          .json({ success: false, message: "Post not found using given id" });
      } else {
        post = await Postjob.findByIdAndUpdate(
          id,
          {
            $set: {
              name,
              schedule,
              state,
              code,
              city,
              zip,
              overview,
              position,
              logo: req.file ? req.file : post.logo,
            },
          },
          { new: true }
        );
        post.save();
        return res.status(200).json({
          success: true,
          message: "Post has been edited successfully",
        });
      }
    } catch (error) {
      return res.status(500).json({ success: false, message: error.message });
    }
  });
});

routes.post("/post-job/fetch-all", adminAccess, async (req, res) => {
  try {
    const jobs = await Postjob.find();
    if (!jobs) {
      return res
        .status(404)
        .json({ success: false, message: "No jobs has been posted yet." });
    } else {
      return res.status(200).json({ success: true, total: jobs.length, jobs });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

routes.get("/post-job/fetch-approved", async (req, res) => {
  try {
    const jobs = await Postjob.find({ isApproved: true });
    if (!jobs) {
      return res
        .status(404)
        .json({ success: false, message: "No jobs has been posted yet." });
    } else {
      return res.status(200).json({ success: true, total: jobs.length, jobs });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

routes.post("/action/post/:id/:action", adminAccess, async (req, res) => {
  try {
    let { reason } = req.body;
    const { action, id } = req.params;
    const pendingPosts = await Postjob.find({ isApproved: false });
    const fetchIndPost = await Postjob.findById(id);
    let postFound = false;

    if (action.toLowerCase() === "accept") {
      let user = await User.findById(fetchIndPost.postedBy);
      if (user) {
        user.job_posted += 1;
        user.save();
      }
      pendingPosts.forEach((post) => {
        if (post.id === id) {
          postFound = true;
          post.isApproved = true;
          post.approvedDate = moment().format("MMMM Do YYYY, h:mm:ss a");
          post.save();
        }
      });

      if (!postFound) {
        return res.status(404).json({
          success: false,
          message: "Post ID not found.",
        });
      }

      return res.status(200).json({
        success: true,
        message: "Post approved successfully.",
      });
    } else if (action.toLowerCase() === "reject") {
      pendingPosts.forEach((post) => {
        if (post.id === id) {
          postFound = true;
        }
      });

      if (postFound) {
        const postDetails = await Postjob.findById(id);
        fs.readdir("./images", (err, files) => {
          if (err) {
            console.error("Error reading image directory.");
          } else {
            files.forEach((file) => {
              if (postDetails.logo.filename !== undefined) {
                if (file === postDetails.logo.filename) {
                  const filePath = path.join("./images", file);
                  fs.unlink(filePath, (err) => {
                    if (err) {
                      console.error("Error deleting image file.");
                    }
                  });
                }
              }
            });
          }
        });
        let user = await User.findById(fetchIndPost.postedBy);
        if (user) {
          postRejectionMessage(
            user.email,
            user.name,
            "Post rejection",
            reason,
            {
              name: fetchIndPost.name,
              location: `${fetchIndPost.state} | ${fetchIndPost.city} | ${fetchIndPost.zip}`,
              date: fetchIndPost.postedDate,
            }
          );
        }
        await Postjob.findByIdAndDelete(id);
        return res.status(200).json({
          success: true,
          message: "Post rejected and deleted successfully.",
        });
      } else {
        return res.status(404).json({
          success: false,
          message: "Post ID not found.",
        });
      }
    } else if (action.toLowerCase() === "delete") {
      const postDetails = await Postjob.findById(id);
      fs.readdir("./images", (err, files) => {
        if (err) {
          console.error("Error reading image directory.");
        } else {
          files.forEach((file) => {
            if (postDetails.logo.filename !== undefined) {
              if (file === postDetails.logo.filename) {
                const filePath = path.join("./images", file);
                fs.unlink(filePath, (err) => {
                  if (err) {
                    console.error("Error deleting image file.");
                  }
                });
              }
            }
          });
        }
      });
      await Postjob.findByIdAndDelete(id);
      return res.status(200).json({
        success: true,
        message: "Post deleted successfully",
      });
    }
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: `Server error: ${error.message}`,
    });
  }
});

routes.post("/action/post/:state", async (req, res) => {
  try {
    let { state } = req.params;
    let { position } = req.body;
    let post = await Postjob.find({ isApproved: true });

    if (!post || post.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "No post available" });
    } else {
      let searchedPost = post.filter((e) => {
        return (
          e.position.some((element) =>
            position.includes(element.toLowerCase())
          ) && e.state.toLowerCase() === state.toLowerCase()
        );
      });
      return res.status(200).json({
        success: true,
        total: searchedPost.length,
        data: searchedPost,
      });
    }
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

routes.post("/action/post/fetch/all/:id", userAccess, async (req, res) => {
  try {
    const { id } = req.params;
    if (String(req.user.id) !== String(id)) {
      return res
        .status(401)
        .json({ success: false, message: "User access denied" });
    }
    let post = await Postjob.find({
      postedBy: req.user.id,
    });
    if (!post) {
      return res.status(404).json({
        success: false,
        message: "No post has been done from this account",
      });
    }
    return res.status(200).json({ success: true, post });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});
module.exports = routes;
