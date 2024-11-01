const express = require("express");
const routes = express.Router();
const PostConst = require("../models/PostConst");
const adminAccess = require("../middleware/adminAccess");
routes.post("/post/rules/post", adminAccess, async (req, res) => {
  try {
    let data = {
      start: "2024-10-01",
      end: "2024-12-01",
    };

    await PostConst.create({
      free_posting: {
        start: data.start,
        end: data.end,
      },
    });

    return res
      .status(200)
      .json({ success: true, message: "Post rules uploaded successfully" });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

routes.put("/post/rules/update/:id", adminAccess, async (req, res) => {
  try {
    const { start, end } = req.body;
    let postRule = await PostConst.findById(req.params.id);
    if (!postRule) {
      return res
        .status(401)
        .json({ success: false, message: "No rules found to update!" });
    }
    await PostConst.findByIdAndUpdate(
      req.params.id,
      { $set: { free_posting: { start, end } } },
      { new: true }
    );
    return res
      .status(200)
      .json({ success: true, message: "Date updated successfully", postRule });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});

routes.post("/post/rules/date/fetch", adminAccess, async (req, res) => {
  try {
    let date = await PostConst.findById("67133b8ac9b1f8fe80b3ee7c");
    if (!date) {
      return res
        .status(404)
        .json({ success: false, message: "Date not available with give id" });
    }
    res.status(200).json({ success: true, date });
  } catch (error) {
    return res.status(500).json({ success: false, message: error.message });
  }
});
module.exports = routes;
