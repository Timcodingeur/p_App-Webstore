import express from "express";
import {
  getAll,
  postUsr,
  getId,
  postCon,
} from "../controllers/UserController.mjs";

const router = express();
router.get("/", getAll);

router.post("/", postUsr);

router.get("/:firstname", getId);

router.post("/login", postCon);

export { router };
