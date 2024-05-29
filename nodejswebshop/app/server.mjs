import express from "express";
import { router } from "./routes/User.mjs";
import fs from "fs";
import cors from 'cors';
import https from "https";

const app = express();


const corsOptions = {
  origin: 'http://127.0.0.1:8081',
};

app.use(cors(corsOptions));
const options = {
  key: fs.readFileSync("./ssl/server.key"),
  cert: fs.readFileSync("./ssl/server.cert"),
};

https.createServer(options, app).listen(8080);

app.use(express.json());
app.use("/users", router);
