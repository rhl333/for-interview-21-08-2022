import dotenv from "dotenv";
dotenv.config();
import cors from "cors";
import express from "express";
import mongoose from "mongoose";
import authorAndBooksRouter from "./routes/authorAndBooks.js";
let server = express();

server.use(cors());

import userRouter from "./routes/user.js";
import homeRouter from "./routes/home.js";

server.use(express.json());
server.use(express.urlencoded({ extended: false }));

server.use("/api/auth", userRouter);
server.use("/", authorAndBooksRouter);
server.use("/", homeRouter);

const start = async () => {
  await mongoose.connect(process.env.DB_URL);

  server.listen(process.env.PORT || 8000, () => console.log(`server is listening on port ${process.env.PORT}`));
};

mongoose.connection.once("open", () => console.log("connected to the database successfully"));
mongoose.connection.on("error", (err) => console.log("some error occured\n", err));

start();
