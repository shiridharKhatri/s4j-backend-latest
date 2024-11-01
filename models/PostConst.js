const mongoose = require("mongoose");
const moment = require("moment");
const postConstSchema = mongoose.Schema({
  free_posting: {
    start: {
      type: String,
      default: "2024-10-01",
    },
    end: {
      type: String,
      default: "2024-12-01",
    },
  },
  updatedOn: {
    type: String,
    default: moment().format("MMMM Do YYYY, h:mm:ss a"),
  },
});
module.exports = mongoose.model("Postconst-details", postConstSchema);
