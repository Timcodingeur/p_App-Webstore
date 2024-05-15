// controllers/UserController.mjs
import crypto from "crypto";
import { pool } from "../db/db.mjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

// Load environment variables from .env file
dotenv.config();

// Ensure the JWT_SECRET is available
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error("JWT_SECRET is not defined in environment variables");
}

// Helper functions
function generateSalt(length = 16) {
  return crypto.randomBytes(length).toString("hex");
}

function hashPassword(password, salt) {
  return crypto.createHmac("sha256", salt).update(password).digest("hex");
}

async function verifyPassword(inputPassword, storedHash, storedSalt) {
  const inputHash = hashPassword(inputPassword, storedSalt);
  console.log("Comparing input hash:", inputHash, "with stored hash:", storedHash);
  return inputHash === storedHash;
}

function decrypt(encryptedText, ivHex, keyData) {
  try {
    const key = Buffer.from(keyData, 'hex').slice(0, 32); // Assure que la clé est de 32 octets
    const iv = Buffer.from(ivHex, "hex");
    console.log("Decrypting with key:", key.toString('hex'), "and IV:", iv.toString('hex'));
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    console.error("Decryption error:", error);
    return null;
  }
}

export const getAll = async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, jwtSecret);

    const [rows] = await pool.query("SELECT firstname, lastname, email, iv_firstname, iv_lastname FROM T_users");
    const decryptedUsers = rows.map((user) => {
      console.log("Decrypting user:", user);
      const firstname = decrypt(user.firstname, user.iv_firstname, decoded.data);
      const lastname = decrypt(user.lastname, user.iv_lastname, decoded.data);

      console.log("Decrypted firstname:", firstname);
      console.log("Decrypted lastname:", lastname);

      if (firstname && lastname && user.email) {
        return { firstname, lastname, email: user.email };
      }
      return null;
    }).filter((user) => user != null);

    console.log("Decrypted users:", decryptedUsers);
    res.json(decryptedUsers);
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
};

export const getId = async (req, res) => {
  try {
    if (!req.headers.authorization) {
      return res.status(401).send("Le token n'est point la");
    }

    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, jwtSecret);
    const userId = req.params.id;

    const [rows] = await pool.query("SELECT firstname, lastname, email, iv_firstname, iv_lastname FROM T_users WHERE id = ?", [userId]);
    const decryptedUsers = rows.map((user) => {
      console.log("Decrypting user:", user);
      const firstname = decrypt(user.firstname, user.iv_firstname, decoded.data);
      const lastname = decrypt(user.lastname, user.iv_lastname, decoded.data);

      console.log("Decrypted firstname:", firstname);
      console.log("Decrypted lastname:", lastname);

      if (firstname && lastname && user.email) {
        console.log("Decrypted:", { firstname, lastname, email: user.email });
        return { firstname, lastname, email: user.email };
      }
      return null;
    }).filter((user) => user !== null);

    if (decryptedUsers.length === 0) {
      return res.status(404).send("User not found");
    }

    console.log("Filtered users:", decryptedUsers);
    res.json(decryptedUsers[0]);
  } catch (err) {
    console.error(err);
    if (err instanceof jwt.JsonWebTokenError) {
      return res.status(401).send("Invalid token");
    }
    res.status(500).send("Internal Server Error");
  }
};

export const postUsr = async (req, res) => {
  const { password, firstname, lastname, email } = req.body;
  console.log("Password:", password, "Firstname:", firstname, "Lastname:", lastname, "Email:", email);

  try {
    const salt = generateSalt();
    const hashedPassword = hashPassword(password, salt);
    const key = Buffer.from(hashedPassword, 'hex').slice(0, 32);
    
    const encryptedFirstname = encryptWithIV(firstname, key);
    const encryptedLastname = encryptWithIV(lastname, key);

    console.log("Encrypted firstname:", encryptedFirstname);
    console.log("Encrypted lastname:", encryptedLastname);

    const [result] = await pool.query(
      "INSERT INTO T_users (firstname, lastname, email, password, salt, iv_firstname, iv_lastname) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [
        encryptedFirstname.encrypted,
        encryptedLastname.encrypted,
        email,
        hashedPassword,
        salt,
        encryptedFirstname.iv,
        encryptedLastname.iv,
      ]
    );

    const userId = result.insertId;
    const token = jwt.sign(
      { data: hashedPassword },
      jwtSecret,
      { expiresIn: "50Y" }
    );

    res.json({ message: "User ajouté!", token });
  } catch (err) {
    console.error(err);
    res.status(500).send(`Internal Server Error: ${err.message}`);
  }
};

export const postCon = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).send("Identifiants invalides.");
    }

    const isValidPassword = await verifyPassword(password, user.password, user.salt);
    console.log("Password verification result:", isValidPassword);
    if (!isValidPassword) {
      return res.status(401).send("Identifiants invalides.");
    }

    const token = jwt.sign(
      { data: user.password },
      jwtSecret,
      { expiresIn: "1h" }
    );

    const firstname = decrypt(user.firstname, user.iv_firstname, user.password);
    const lastname = decrypt(user.lastname, user.iv_lastname, user.password);

    res.json({ 
      token: token, 
      message: "Connexion réussie !",
      user: {
        firstname,
        lastname,
        email: user.email
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Erreur du serveur interne.");
  }
};

const findUserByEmail = async (email) => {
  try {
    console.log("Looking for email:", email);
    const [rows] = await pool.query("SELECT * FROM T_users WHERE email = ?", [email]);

    if (rows.length > 0) {
      console.log("User found:", rows[0]);
      return rows[0]; // Retourne le premier utilisateur correspondant
    } else {
      console.log("No user found with the email.");
    }
    return null; 
  } catch (error) {
    console.error("Error in findUserByEmail:", error);
    throw error; 
  }
};


function encryptWithIV(text, key) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return { encrypted, iv: iv.toString("hex") };
}
