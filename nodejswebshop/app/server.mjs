import express from "express";
import { router } from "./routes/User.mjs";
import fs from "fs";
import https from "https";

const app = express();

const options = {
  key: fs.readFileSync("./ssl/server.key"),
  cert: fs.readFileSync("./ssl/server.cert"),
};

https.createServer(options, app).listen(8080);

app.use(express.json());
app.use("/user", router);
