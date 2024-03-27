import express from "express";
import { get } from "../controllers/UserController.mjs";

const router = express();
router.get("/", get);
export { router };
