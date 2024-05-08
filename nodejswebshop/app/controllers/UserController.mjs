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

        console.log("daicrpté:", { firstname, lastname, email }); // Log pour diagnostic

        if (firstname && lastname) {
          // vérifie que les noms ne sont pas null
          return { firstname, lastname, email };
        }
      })
      .filter((user) => user != null); // Filtre les utilisateurs null

    console.log("yiouseur:", decryptedUsers); // Vérifier les utilisateurs filtrés
    res.json(decryptedUsers);
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
};

export const getId = async (req, res) => {
  try {
    // Vérifie si le token est présent dans le header
    if (!req.headers.authorization) {
      return res.status(401).send("Le token n'est point la");
    }

    const token = req.headers.authorization.split(" ")[1];
    if (!token) {
      return res.status(401).send("Authorisation de noob");
    }

    const decoded = jwt.verify(token, secretKey);

    // Utilisez l'ID de l'URL pour récupérer les informations spécifiques de l'utilisateur
    const userId = req.params.id;

    const [rows] = await pool.query(
      "SELECT firstname, lastname, email, iv FROM T_users WHERE id = ?",
      [userId]
    );

    const decryptedUsers = rows
      .map((user) => {
        const firstname = decrypt(user.firstname, user.iv, decoded.data);
        const lastname = decrypt(user.lastname, user.iv, decoded.data);
        const email = decryptWithoutIV(user.email, user.iv, decoded.data);

        if (firstname && lastname && email) {
          console.log("Decrypted:", { firstname, lastname, email });
          return { firstname, lastname, email };
        }
        return null;
      })
      .filter((user) => user !== null);

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

const decrypt = (encryptedText, ivHex, keyData) => {
  try {
    console.log("IV Hex:", ivHex); // Vérifier la sortie de l'IV en hexadécimal
    const key = Buffer.from(keyData.substring(0, 32)); // Prend 32 caractères du mdp (key)
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
const decryptWithoutIV = (encryptedText, keyData) => {
  try {
    const key = Buffer.from(keyData.substring(0, 32)); // Utiliser les 32 premiers caractères du hash comme clé
    const decipher = crypto.createDecipher("aes-256-ecb", key);
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    console.error("Decryption error:", error);
    return null; // Retourner null en cas d'erreur de déchiffrement
  }
};
export const postCon = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Rechercher l'utilisateur par e-mail
    const user = await findUserByEmail(email, password); // Supposons une fonction qui récupère l'utilisateur par e-mail
    if (!user) {
      return res.status(401).send("Identifiants invalides.");
    }

    // Comparaison des mots de passe
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).send("Identifiants invalides.");
    }

    // Génération d'un token JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET, // Utilisez une variable d'environnement pour le secret
      { expiresIn: "1h" } // Spécifiez la durée de validité du token
    );

    res.json({ token: token, message: "Connexion réussie !" });
  } catch (error) {
    console.error(error);
    res.status(500).send("Erreur du serveur interne.");
  }
};

const findUserByEmail = (email, password) => {
  try {
    // Crypter l'email avec une clé dérivée du mot de passe
    const hash = crypto.createHash("sha512").update(password).digest("hex");
    const key = Buffer.from(hash.substring(0, 32)); // Utiliser les 32 premiers caractères du hash comme clé
    const encryptedEmail = simpleEncrypt(email, key);

    // Requête pour trouver l'utilisateur par email crypté
    const query = "SELECT * FROM T_users WHERE email = ?";
    const [rows] = pool.query(query, [encryptedEmail]);

    // Si un utilisateur est trouvé, retourner les données de l'utilisateur
    if (rows.length > 0) {
      return rows[0]; // Retourne le premier utilisateur correspondant
    }
    return null; // Retourner null si aucun utilisateur n'est trouvé
  } catch (error) {
    console.error("Error in findUserByEmail:", error);
    throw error; // Relancez l'erreur pour une meilleure gestion des erreurs
  }
};

export const postUsr = async (req, res) => {
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
  );

  try {
    // Hashing password to create a key
    const hash = crypto.createHash("sha512").update(password).digest("hex");
    const key = Buffer.from(hash.substring(0, 32)); // Utiliser les 32 premiers caractères du hash comme clé
    // Chiffrer les données
    const encryptedFirstname = encryptWithIV(firstname, key);
    const encryptedLastname = encryptWithIV(lastname, key);
    const encryptedEmail = simpleEncrypt(email, key);

    // Signature JWT
    const token = jwt.sign({ data: hash }, secretKey, { expiresIn: "50Y" });

    // Insertion en base de données
    await pool.query(
      "INSERT INTO T_users (firstname, lastname, email, password, iv) VALUES (?, ?, ?, ?, ?)",
      [
        encryptedFirstname.encrypted,
        encryptedLastname.encrypted,
        encryptedEmail,
        hash,
        encryptedFirstname.iv,
      ]
    );

    res.json({ message: "User ajouté!", token });
  } catch (err) {
    console.error(err);
    res.status(500).send(`Internal Server Error: ${err.message}`);
  }
};
const simpleEncrypt = (text, key) => {
  const cipher = crypto.createCipher("aes-256-ecb", key);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
};
const encryptWithIV = (text, key) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return { encrypted, iv: iv.toString("hex") };
};
