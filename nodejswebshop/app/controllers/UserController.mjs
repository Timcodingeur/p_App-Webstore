import crypto from "crypto";
import { pool } from "../db/db.mjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

//assure l'appel des variable d'environement
dotenv.config();

//assure que la clé pour faire le jwt existe
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error("JWT_SECRET is not defined in environment variables");
}

//genère le sel du mot de passe
function generateSalt(length = 16) {
  return crypto.randomBytes(length).toString("hex");
}

//hash de mot de passe
function hashPassword(password, salt) {
  return crypto.createHmac("sha256", salt).update(password).digest("hex");
}

//vérifie les hash pour detecter le bon mdp
async function verifyPassword(inputPassword, storedHash, storedSalt) {
  const inputHash = hashPassword(inputPassword, storedSalt);
  console.log("Comparing input hash:", inputHash, "with stored hash:", storedHash);
  return inputHash === storedHash;
}

//permet de decripter avec la clé iv et le hash les information précédement cryptée
function decrypt(encryptedText, ivHex, keyData) {
  try {
    //coupe le hash pour créé la clé
    const key = Buffer.from(keyData, 'hex').slice(0, 32); 
    //recup l'iv 
    const iv = Buffer.from(ivHex, "hex");
    //log pour les test
    console.log("Decrypting with key:", key.toString('hex'), "and IV:", iv.toString('hex'));
    //decrypt avec descipheriv (iv vu que j'ai une iv)
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    //met les info dans decrypted
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    console.error("Decryption error:", error);
    return null;
  }
}

//permet de récupéré les info, il récupère que ce qu'il a pu décripté
//donc l'utilisateur a que accès a ses info
export const getAll = async (req, res) => {
  try {
    //prend le token du header
    const token = req.headers.authorization.split(" ")[1];
    //verifie le token
    const decoded = jwt.verify(token, jwtSecret);

    //fait un select
    const [rows] = await pool.query("SELECT firstname, lastname, email, iv_firstname, iv_lastname FROM T_users");
    //passe sur tout les info, essais de decripter
    const decryptedUsers = rows.map((user) => {
      console.log("Decrypting user:", user);
      const firstname = decrypt(user.firstname, user.iv_firstname, decoded.data);
      const lastname = decrypt(user.lastname, user.iv_lastname, decoded.data);

      console.log("Decrypted firstname:", firstname);
      console.log("Decrypted lastname:", lastname);
      //et pour ce qu'il sais pas decrypter il return rien
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

//permet de trouver la personne a partir de l'id (pas forcèment utile il fonctionne comme le get all)
export const getId = async (req, res) => {
  try {
    if (!req.headers.authorization) {
      return res.status(401).send("Le token n'est point là");
    }
    // Prend le token et la clé secrète
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, jwtSecret);
    const firstnameToFind = req.params.firstname;

    // Récupère tous les utilisateurs
    const [rows] = await pool.query("SELECT firstname, lastname, email, iv_firstname, iv_lastname FROM T_users");

    const decryptedUsers = rows.map((user) => {
      console.log("Decrypting user:", user);
      const decryptedFirstname = decrypt(user.firstname, user.iv_firstname, decoded.data);
      const decryptedLastname = decrypt(user.lastname, user.iv_lastname, decoded.data);

      console.log("Decrypted firstname:", decryptedFirstname);
      console.log("Decrypted lastname:", decryptedLastname);

      if (decryptedFirstname && decryptedLastname && user.email) {
        return { firstname: decryptedFirstname, lastname: decryptedLastname, email: user.email };
      }
      return null;
    }).filter((user) => user !== null);

    // Filtre l'utilisateur par prénom
    let user = decryptedUsers.find(u => u.firstname === firstnameToFind);

    if (!user) {
      // Vérifie si l'utilisateur est administrateur
      const [adminRows] = await pool.query("SELECT isAdmin FROM T_users WHERE email = ?", [decoded.email]);
      const isAdmin = adminRows.length > 0 && adminRows[0].isAdmin === 1;
      console.log(`User is admin: ${isAdmin}`);

      if (isAdmin) {
        // Récupère tous les utilisateurs à nouveau
        const [adminRows] = await pool.query("SELECT firstname, lastname, email, iv_firstname, iv_lastname, password FROM T_users");

        const adminDecryptedUsers = adminRows.map((user) => {
          console.log("Decrypting user for admin:", user);
          const decryptedFirstname = decrypt(user.firstname, user.iv_firstname, user.password);
          const decryptedLastname = decrypt(user.lastname, user.iv_lastname, user.password);

          console.log("Admin Decrypted firstname:", decryptedFirstname);
          console.log("Admin Decrypted lastname:", decryptedLastname);

          if (decryptedFirstname && decryptedLastname && user.email) {
            return { firstname: decryptedFirstname, lastname: decryptedLastname, email: user.email };
          }
          return null;
        }).filter((user) => user !== null);

        // Filtre l'utilisateur par prénom pour l'administrateur
        user = adminDecryptedUsers.find(u => u.firstname === firstnameToFind);
        console.log(`User found by admin: ${user !== undefined}`);
      }
    }

    if (!user) {
      return res.status(404).send("User not found");
    }

    console.log("Filtered user:", user);
    res.json(user);
  } catch (err) {
    console.error(err);
    if (err instanceof jwt.JsonWebTokenError) {
      return res.status(401).send("Invalid token");
    }
    res.status(500).send("Internal Server Error");
  }
};





//permet de post un user dans la db, il récupère le token avec
export const postUsr = async (req, res) => {
  const { password, firstname, lastname, email } = req.body;
  console.log("Password:", password, "Firstname:", firstname, "Lastname:", lastname, "Email:", email);

  try {
    //appel le generateSalt
    const salt = generateSalt();
    //hash de mdp
    const hashedPassword = hashPassword(password, salt);
    const key = Buffer.from(hashedPassword, 'hex').slice(0, 32);
    //on ne crypte pas l'email
    const encryptedFirstname = encryptWithIV(firstname, key);
    const encryptedLastname = encryptWithIV(lastname, key);

    console.log("Encrypted firstname:", encryptedFirstname);
    console.log("Encrypted lastname:", encryptedLastname);

    //on insert sa dans l'email
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
    //il signe le token (j'ai mis 50 an pour les test il expire jamais)
    const token = jwt.sign(
      { data: hashedPassword },
      jwtSecret,
      { expiresIn: "50Y" }
    );

    res.status(201).send({ message: "User ajouté!", token });
  } catch (err) {
    console.error(err);
    res.status(500).send(`Internal Server Error: ${err.message}`);
  }
};

//permet de se connecter, il fait un post avec sont mot depasse et sont email
//et il a ses info et sont token
export const postCon = async (req, res) => {
  const { email, password } = req.body;

  try {
    //il appel le findd user email pour trouver le user
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).send("Identifiants invalides.");
    }
    //il vérifie les mot de passe
    const isValidPassword = await verifyPassword(password, user.password, user.salt);
    console.log("Password verification result:", isValidPassword);
    if (!isValidPassword) {
      //si les identifiant existe pas il dit que c pas valide
      return res.status(401).send("Identifiants invalides.");
    }
    //signe le token
    const token = jwt.sign(
      { data: user.password },
      jwtSecret,
      { expiresIn: "1h" }
    );
    //on ne decrypt pas l'email car on l'a pas cryptée
    const firstname = decrypt(user.firstname, user.iv_firstname, user.password);
    const lastname = decrypt(user.lastname, user.iv_lastname, user.password);
    //si sa a reussi il met le token, et il écris les info du user
    res.status(201).send({ 
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

//trovue les info de la personne grace a sont email
const findUserByEmail = async (email) => {
  try {
    //il cherche par rapport a l'email de la personne si des gent existe si il a pas trouvé il dit not found
    console.log("Looking for email:", email);
    const [rows] = await pool.query("SELECT * FROM T_users WHERE email = ?", [email]);

    if (rows.length > 0) {
      console.log("User found:", rows[0]);
      return rows[0]; 
    } else {
      console.log("No user found with the email.");
    }
    return null; 
  } catch (error) {
    console.error("Error in findUserByEmail:", error);
    throw error; 
  }
};

//encrypte les information du l'utilisateur 
function encryptWithIV(text, key) {
  //il créé une iv avec des randombyte
  const iv = crypto.randomBytes(16);
  //il encripte avec l'iv et la clé qu'on avais créé a partir du mot de passe
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  //on return ce qui est crypté et l'iv
  return { encrypted, iv: iv.toString("hex") };
}
