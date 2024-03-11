const mongoose = require("mongoose");
const cors = require("cors");
const express = require("express");
require("dotenv").config();

const user = require("./route/user.route");

const server = express();
server.use(cors());
server.use(express.json());

mongoose
  .connect("mongodb://0.0.0.0:27017/Laxmi_Chit_Fund")
  .then(() => {
    console.log("MongoDB connection succesfull");
  })
  .catch((error) => {
    console.error(error);
  });

server.use("/api/v1", user);

const port = process.env.PORT || 7410;

server.listen(port, () => {
  console.log(`Server is running on ${port}`);
});
