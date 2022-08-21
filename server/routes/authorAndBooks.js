import express from "express";
import { createData, deleteBook } from "../controllers/authorAndBook.js";
import authHome from "../middlewares/homePage.js";

const router = express.Router();
router.use(authHome);

router.post("/create", createData);

router.delete("/delete", deleteBook);

export default router;
