// controllers/UserController.mjs
import mysql from "mysql2/promise";

const pool = mysql.createPool({
  // Vos paramètres de connexion
  user: "root",
  host: "localhost",
  database: "db_user",
  password: "root",
  port: "6033",
});

export const get = async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM t_users");
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
};
