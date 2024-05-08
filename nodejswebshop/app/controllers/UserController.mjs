// controllers/UserController.mjs
import crypto from "crypto";
import { pool } from "../db/db.mjs";
import jwt from "jsonwebtoken";
import { secretKey } from "../db/secretkey.mjs";

//mettre system decryptage ici, a partir du hash du mot de passe
//de hash du mot de passe est mis dans le header
export const getAll = async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1]; // Extrait le token du header
    const decoded = jwt.verify(token, secretKey); // Vérifie le token

    const [rows] = await pool.query(
      "SELECT firstname, lastname, email, iv FROM T_users"
    );
    const decryptedUsers = rows
      .map((user) => {
        const firstname = decrypt(user.firstname, user.iv, decoded.data);
        const lastname = decrypt(user.lastname, user.iv, decoded.data);
        const email = decrypt(user.email, user.iv, decoded.data);

        console.log("Decrypted:", { firstname, lastname, email }); // Log pour diagnostic

        if (firstname && lastname) {
          // vérifie que les noms ne sont pas null
          return { firstname, lastname, email };
        }
      })
      .filter((user) => user != null); // Filtre les utilisateurs null

    console.log("Filtered users:", decryptedUsers); // Vérifier les utilisateurs filtrés
    res.json(decryptedUsers);
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
};
export const getId = async (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1]; // Extrait le token du header
    const decoded = jwt.verify(token, secretKey); // Vérifie le token

    const [rows] = await pool.query(
      "SELECT firstname, lastname, email, iv FROM T_users"
    );
    const decryptedUsers = rows
      .map((user) => {
        const firstname = decrypt(user.firstname, user.iv, decoded.data);
        const lastname = decrypt(user.lastname, user.iv, decoded.data);
        const email = decrypt(user.email, user.iv, decoded.data);

        console.log("Decrypted:", { firstname, lastname, email }); // Log pour diagnostic

        if (firstname && lastname) {
          // vérifie que les noms ne sont pas null
          return { firstname, lastname, email };
        }
      })
      .filter((user) => user != null); // Filtre les utilisateurs null

    console.log("Filtered users:", decryptedUsers); // Vérifier les utilisateurs filtrés
    res.json(decryptedUsers);
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
};
const decrypt = (encryptedText, ivHex, keyData) => {
  try {
    console.log("IV Hex:", ivHex); // Vérifier la sortie de l'IV en hexadécimal
    const key = Buffer.from(keyData.substring(0, 32));
    const iv = Buffer.from(ivHex, "hex"); // Convertit la chaîne hexadécimale en Buffer
    console.log("IV Buffer:", iv); // Voir la représentation buffer de l'IV
    console.log("IV length:", iv.length); // Devrait afficher 16

    if (iv.length !== 16) {
      throw new Error("Invalid IV length: " + iv.length);
    }

    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch {
    return null;
  }
};

export const post = async (req, res) => {
  const { password, firstname, lastname, email } = req.body;
  console.log(
    "Password:",
    password,
    "Firstname:",
    firstname,
    "Lastname:",
    lastname,
    "Email:",
    email
  ); // Ajouter ce log
  try {
    const { password, firstname, lastname, email } = req.body;
    const hash = crypto.createHash("sha512").update(password).digest("hex");
    const key = Buffer.from(hash.substring(0, 32));
    const iv = crypto.randomBytes(16);
    if (iv.length !== 16) {
      throw new Error("Invalid IV length: " + iv.length);
    }

    // Fonction de chiffrement
    const encrypt = (text) => {
      const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
      let encrypted = cipher.update(text, "utf8", "hex");
      encrypted += cipher.final("hex");
      return encrypted;
    };
    const ivHex = iv.toString("hex"); // Convertit le Buffer de l'IV en chaîne hexadécimale

    // Chiffrer les données
    const encryptedFirstname = encrypt(firstname);
    const encryptedLastname = encrypt(lastname);
    const encryptedEmail = encrypt(email);

    const token = jwt.sign({ data: hash }, secretKey, { expiresIn: "50Y" });

    const [rows] = await pool.query(
      "INSERT INTO T_users (firstname, lastname, email, password, iv) VALUES (?, ?, ?, ?, ?)",
      [encryptedFirstname, encryptedLastname, encryptedEmail, hash, ivHex]
    );
    const ivu = Buffer.from(ivHex, "hex");
    if (ivu.length !== 16) {
      throw new Error("Invalid IV length: " + iv.length);
    }
    res.json({ message: "User ajouté!", token });
  } catch (err) {
    console.error(err);
    res.status(500).send(`Internal Server Error: ${err.message}`);
  }
};
