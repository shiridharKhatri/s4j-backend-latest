const mongoose = require("mongoose");
const moment = require("moment");
const postjobSchema = mongoose.Schema({
  postedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "user-details" || "admin-details",
    require: true,
  },
  name: {
    type: String,
    require: true,
  },
  schedule: {
    type: [String],
    require: true,
  },
  state: {
    type: String,
    require: true,
  },
  code: {
    type: String,
    require: true,
  },
  city: {
    type: String,
    require: true,
  },
  zip: {
    type: String,
    require: true,
  },
  overview: {
    type: String,
    require: true,
  },
  logo: {
    type: Object,
    default: { filename: "none" },
  },
  position: {
    type: [String],
    require: true,
  },
  isApproved: {
    type: Boolean,
    default: false,
  },
  approvedDate: {
    type: String,
  },

  postedDate: {
    type: String,
    default: moment().format("MMMM Do YYYY, h:mm:ss a"),
  },
});
module.exports = mongoose.model("post-details", postjobSchema);
