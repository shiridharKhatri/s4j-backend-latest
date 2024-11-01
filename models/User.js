const mongoose = require("mongoose");
const moment = require("moment");
const userSchema = mongoose.Schema({
  name: {
    type: String,
    require: true,
  },
  email: {
    type: String,
    require: true,
  },
  password: {
    type: String,
    require: true,
  },
  verificationCode: {
    type: Number,
    default: null,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  search_limit: {
    type: Number,
    default: 3,
  },
  posting_limit: {
    type: Number,
    default: 1,
  },
  job_posted: {
    type: Number,
    default: 0,
  },
  accountCreatedDate: {
    type: String,
    default: moment().format("MMMM Do YYYY, h:mm:ss a"),
  },
});
module.exports = mongoose.model("user-details", userSchema);
