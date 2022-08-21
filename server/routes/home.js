import express from "express";
import { home } from "../controllers/home.js";
import homeAuth from "../middlewares/homePage.js";

const router = express.Router();

router.use(homeAuth);

router.get("/", home);

export default router;
