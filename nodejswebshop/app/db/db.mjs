import mysql from "mysql2/promise";

export const pool = mysql.createPool({
  host: "db",
  port: "3306",
  user: "root",
  password: "root",
  database: "db_project183",
});
