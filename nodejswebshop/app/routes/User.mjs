import express from "express";
import { getAll, post, getId } from "../controllers/UserController.mjs";

const router = express();
router.get("/", getAll);

router.post("/", post);

router.get("/:id", getId);
export { router };
