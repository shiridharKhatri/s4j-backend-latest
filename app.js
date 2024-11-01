const express = require("express");
const connectToDatabase = require("./database/db");
const dotenv = require("dotenv");
const cors = require("cors");
const app = express();
const PORT = process.env.PORT || 5000;
dotenv.config("./.env");
const url = process.env.DATABASE_URL;
app.use(cors());
app.use(express.json());
app.use("/image", express.static("images"));
app.use("/auth", require("./routes/admin"));
app.use("/api/jobs", require("./routes/post"));
app.use("/user", require("./routes/user"));
app.use("/api/payment", require("./routes/payment"));
app.use("/api/analytics", require("./routes/analytics"));
app.use("/api/postRules", require('./routes/postconst'))
connectToDatabase(url)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Listening to port ${PORT}`);
    });
  })
  .catch((error) => {
    console.log(error);
  });
