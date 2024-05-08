import mysql from "mysql2/promise";

export const pool = mysql.createPool({
  host: "172.18.0.2",
  port: "3306",
  user: "root",
  password: "root",
  database: "db_project183",
});
