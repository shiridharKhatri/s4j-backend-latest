const mongoose = require("mongoose");
const moment = require("moment");
const adminSchema = mongoose.Schema({
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
  role: {
    type: String,
    default: "admin",
  },
  verificationCode: {
    type: Number,
    default: null,
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  createdDate: {
    type: String,
    default: moment().format("MMMM Do YYYY, h:mm:ss a"),
  },
});
module.exports = mongoose.model("admin-details", adminSchema);
