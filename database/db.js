const mongoose = require("mongoose");
const connectToDatabase = (url) => {
  const connection = mongoose.connect(url);
  try {
    if (connection) {
      console.log(`Connected to database successfully!`);
    }
    return connection;
  } catch (error) {
    return console.log(error);
  }
};
module.exports = connectToDatabase;
