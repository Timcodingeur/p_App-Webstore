import crypto from "crypto";
import { pool } from "../db/db.mjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

// Assure l'appel des variables d'environnement
dotenv.config();

// Assure que la clé pour faire le jwt existe
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  throw new Error("JWT_SECRET is not defined in environment variables");
}

// Génère le sel du mot de passe
function generateSalt(length = 16) {
  return crypto.randomBytes(length).toString("hex");
}

// Hash de mot de passe
function hashPassword(password, salt) {
  return crypto.createHmac("sha256", salt).update(password).digest("hex");
}

// Vérifie les hash pour détecter le bon mdp
async function verifyPassword(inputPassword, storedHash, storedSalt) {
  const inputHash = hashPassword(inputPassword, storedSalt);
  console.log("Comparing input hash:", inputHash, "with stored hash:", storedHash);
  return inputHash === storedHash;
}

// Permet de décrypter avec la clé iv et le hash les informations précédemment cryptées
function decrypt(encryptedText, ivHex, keyData) {
  try {
    // Coupe le hash pour créer la clé
    const key = Buffer.from(keyData, 'hex').slice(0, 32); 
    // Récupère l'iv 
    const iv = Buffer.from(ivHex, "hex");
    // Log pour les tests
    console.log("Decrypting with key:", key.toString('hex'), "and IV:", iv.toString('hex'));
    // Décryptage avec decipheriv (iv vu que j'ai une iv)
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    // Met les informations dans decrypted
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (error) {
    console.error("Decryption error:", error);
    return null;
  }
}

// Encrypte les informations de l'utilisateur 
function encryptWithIV(text, key) {
  // Il créé une iv avec des randombytes
  const iv = crypto.randomBytes(16);
  // Il encrypte avec l'iv et la clé qu'on avait créée à partir du mot de passe
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  // On return ce qui est crypté et l'iv
  return { encrypted, iv: iv.toString("hex") };
}

// Permet de récupérer les informations, il récupère que ce qu'il a pu décrypté
// Donc l'utilisateur a que accès à ses informations
export const getAll = async (req, res) => {
  try {
    if (!req.headers.authorization) {
      return res.status(401).send("Le token n'est point là");
    }

    // Prend le token du header
    const token = req.headers.authorization.split(" ")[1];
    // Vérifie le token
    const decoded = jwt.verify(token, jwtSecret);

    // Récupère les informations de l'utilisateur actuel
    const [userRow] = await pool.query("SELECT email, iv_email FROM T_users WHERE password = ?", [decoded.data]);

    if (userRow.length === 0) {
      return res.status(404).send("User not found");
    }

    // Décrypte l'email de l'utilisateur actuel
    const user = userRow[0];
    const decryptedEmail = decrypt(user.email, user.iv_email, decoded.data);

    if (!decryptedEmail) {
      return res.status(404).send("Email decryption failed");
    }
    //dit l'email decripté
    console.log("Decrypted email:", decryptedEmail);

    // Vérifie si l'utilisateur est administrateur
    const [adminRows] = await pool.query("SELECT isAdmin FROM T_users WHERE email = ?", [user.email]);
    const isAdmin = adminRows.length > 0 && adminRows[0].isAdmin === 1;
    console.log(`isAdmin value from DB: ${isAdmin}`);

    // Récupère tous les utilisateurs
    const [rows] = await pool.query("SELECT firstname, lastname, email, iv_firstname, iv_lastname, iv_email FROM T_users");

    // Décrypte les informations pour tous les utilisateurs
    let decryptedUsers = rows.map((user) => {
      console.log("Decrypting user:", user);
      const firstname = decrypt(user.firstname, user.iv_firstname, decoded.data);
      const lastname = decrypt(user.lastname, user.iv_lastname, decoded.data);
      const email = decrypt(user.email, user.iv_email, decoded.data);
      //log pour les test
      console.log("Decrypted firstname:", firstname);
      console.log("Decrypted lastname:", lastname);
      console.log("Decrypted email:", email);

      // Retourne seulement les utilisateurs dont les informations ont été correctement décryptées
      if (firstname && lastname && email) {
        return { firstname, lastname, email };
      }
      return null;
    }).filter((user) => user != null);

    if (isAdmin) {
      console.log("User is admin");

      // Récupère tous les utilisateurs à nouveau pour l'administrateur, cette fois si il décrypte via le mot de passe directement lié au user dans la db
      const [allRows] = await pool.query("SELECT firstname, lastname, email, iv_firstname, iv_lastname, iv_email, password FROM T_users");

      decryptedUsers = allRows.map((user) => {
        console.log("Decrypting user for admin:", user);
        const decryptedFirstname = decrypt(user.firstname, user.iv_firstname, user.password);
        const decryptedLastname = decrypt(user.lastname, user.iv_lastname, user.password);
        const decryptedEmail = decrypt(user.email, user.iv_email, user.password);
        //log pour les test
        console.log("Admin Decrypted firstname:", decryptedFirstname);
        console.log("Admin Decrypted lastname:", decryptedLastname);
        console.log("Admin Decrypted email:", decryptedEmail);
        //return le tout, si c'est null il retourne rien
        if (decryptedFirstname && decryptedLastname && decryptedEmail) {
          return { firstname: decryptedFirstname, lastname: decryptedLastname, email: decryptedEmail };
        }
        return null;
      }).filter((user) => user !== null);
    }
    //dit les user decripté dans le log
    console.log("Decrypted users:", decryptedUsers);
    res.json(decryptedUsers);
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
};



// Permet de trouver la personne à partir de l'id (pas forcément utile, il fonctionne comme le getAll)
export const getId = async (req, res) => {
  try {
    if (!req.headers.authorization) {
      return res.status(401).send("Le token n'est point là");
    }

    // Prend le token et la clé secrète
    const token = req.headers.authorization.split(" ")[1];
    const decoded = jwt.verify(token, jwtSecret);
    const firstnameToFind = req.params.firstname;

    // Récupère les informations de l'utilisateur actuel
    const [userRow] = await pool.query("SELECT email, iv_email FROM T_users WHERE password = ?", [decoded.data]);

    if (userRow.length === 0) {
      return res.status(404).send("User not found");
    }

    // Décrypte l'email de l'utilisateur actuel
    const currentUser = userRow[0];
    const decryptedEmail = decrypt(currentUser.email, currentUser.iv_email, decoded.data);

    if (!decryptedEmail) {
      return res.status(404).send("Email decryption failed");
    }

    console.log("Decrypted email:", decryptedEmail);

    // Vérifie si l'utilisateur est administrateur
    const [adminRows] = await pool.query("SELECT isAdmin FROM T_users WHERE email = ?", [currentUser.email]);
    const isAdmin = adminRows.length > 0 && adminRows[0].isAdmin === 1;
    console.log(`isAdmin value from DB: ${isAdmin}`);

    // Récupère tous les utilisateurs
    const [rows] = await pool.query("SELECT firstname, lastname, email, iv_firstname, iv_lastname, iv_email FROM T_users");

    const decryptedUsers = rows.map((user) => {
      console.log("Decrypting user:", user);
      const decryptedFirstname = decrypt(user.firstname, user.iv_firstname, decoded.data);
      const decryptedLastname = decrypt(user.lastname, user.iv_lastname, decoded.data);
      const decryptedEmail = decrypt(user.email, user.iv_email, decoded.data);

      console.log("Decrypted firstname:", decryptedFirstname);
      console.log("Decrypted lastname:", decryptedLastname);
      console.log("Decrypted email:", decryptedEmail);

      if (decryptedFirstname && decryptedLastname && decryptedEmail) {
        return { firstname: decryptedFirstname, lastname: decryptedLastname, email: decryptedEmail };
      }
      return null;
    }).filter((user) => user !== null);

    // Filtre l'utilisateur par prénom
    let user = decryptedUsers.find(u => u.firstname === firstnameToFind);

    if (!user && isAdmin) {
      console.log("User is admin, searching all users");

      // Récupère tous les utilisateurs à nouveau, y compris les mots de passe pour les administrateurs
      const [allRows] = await pool.query("SELECT firstname, lastname, email, iv_firstname, iv_lastname, iv_email, password FROM T_users");

      const adminDecryptedUsers = allRows.map((user) => {
        console.log("Decrypting user for admin:", user);
        const decryptedFirstname = decrypt(user.firstname, user.iv_firstname, user.password);
        const decryptedLastname = decrypt(user.lastname, user.iv_lastname, user.password);
        const decryptedEmail = decrypt(user.email, user.iv_email, user.password);

        console.log("Admin Decrypted firstname:", decryptedFirstname);
        console.log("Admin Decrypted lastname:", decryptedLastname);
        console.log("Admin Decrypted email:", decryptedEmail);

        if (decryptedFirstname && decryptedLastname && decryptedEmail) {
          return { firstname: decryptedFirstname, lastname: decryptedLastname, email: decryptedEmail };
        }
        return null;
      }).filter((user) => user !== null);

      // Filtre l'utilisateur par prénom pour l'administrateur
      user = adminDecryptedUsers.find(u => u.firstname === firstnameToFind);    
      console.log(`User found by admin: ${user !== undefined}`);
    }
                
    if (!user) {
      return res.status(404).send("User not found");
    }

    console.log("Filtered user:", user);
    res.json(user);
  } catch (err) {
    console.error("Error in getId:", err);
    if (err instanceof jwt.JsonWebTokenError) {
      return res.status(401).send("Invalid token");
    }
    res.status(500).send("Internal Server Error");
  }
};


// Permet de post un user dans la db, il récupère le token avec
export const postUsr = async (req, res) => {
  const { password, firstname, lastname, email } = req.body;
  console.log("Password:", password, "Firstname:", firstname, "Lastname:", lastname, "Email:", email);

  try {
    // Appel le generateSalt
    const salt = generateSalt();
    // Hash de mdp
    const hashedPassword = hashPassword(password, salt);
    const key = Buffer.from(hashedPassword, 'hex').slice(0, 32);
    // Crypte l'email
    const encryptedEmail = encryptWithIV(email, key);
    const encryptedFirstname = encryptWithIV(firstname, key);
    const encryptedLastname = encryptWithIV(lastname, key);
    //log pour les test
    console.log("Encrypted email:", encryptedEmail);
    console.log("Encrypted firstname:", encryptedFirstname);
    console.log("Encrypted lastname:", encryptedLastname);

    // On insert cela dans la base de données
    const [result] = await pool.query(
      "INSERT INTO T_users (firstname, lastname, email, password, salt, iv_firstname, iv_lastname, iv_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [
        encryptedFirstname.encrypted,
        encryptedLastname.encrypted,
        encryptedEmail.encrypted,
        hashedPassword,
        salt,
        encryptedFirstname.iv,
        encryptedLastname.iv,
        encryptedEmail.iv,
      ]
    );

    const userId = result.insertId;
    // Il signe le token (j'ai mis 50 ans pour les tests)
    const token = jwt.sign(
      { data: hashedPassword },
      jwtSecret,
      { expiresIn: "50Y" }
    );
    //dit quand le user est ajouté
    res.status(201).send({ message: "User ajouté!", token });
  } catch (err) {
    console.error(err);
    res.status(500).send(`Internal Server Error: ${err.message}`);
  }
};

// Permet de se connecter, il fait un post avec son mot de passe et son email
// Et il a ses informations et son token
export const postCon = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Il appelle le findUserByEmail pour trouver le user
    const user = await findUserByEmail(email, password);
    if (!user) {
      return res.status(401).send("Identifiants invalides.");
    }
    // Il vérifie les mots de passe
    const isValidPassword = await verifyPassword(password, user.password, user.salt);
    console.log("Password verification result:", isValidPassword);
    if (!isValidPassword) {
      // Si les identifiants n'existent pas, il dit que ce n'est pas valide
      return res.status(401).send("Identifiants invalides.");
    }
    // Signe le token
    const token = jwt.sign(
      { data: user.password },
      jwtSecret,
      { expiresIn: "1h" }
    );
    // Décrypte l'email, le prénom et le nom
    const firstname = decrypt(user.firstname, user.iv_firstname, user.password);
    const lastname = decrypt(user.lastname, user.iv_lastname, user.password);
    const decryptedEmail = decrypt(user.email, user.iv_email, user.password);
    // Si cela a réussi, il met le token et écrit les informations du user
    res.status(201).send({ 
      token: token, 
      message: "Connexion réussie !",
      user: {
        firstname,
        lastname,
        email: decryptedEmail
      }
    });
  } catch (error) {
    //si il y'a une erreur durant la connection
    console.error(error);
    res.status(500).send("Erreur du serveur interne.");
  }
};

// Trouve les informations de la personne grâce à son email
const findUserByEmail = async (email, password) => {
  try {
    // Récupère tous les utilisateurs
    const [rows] = await pool.query("SELECT * FROM T_users");
    //trouve via l'email crypté
    const decryptedUsers = rows.map((user) => {
      console.log("Decrypting user for email match:", user);
      const decryptedEmail = decrypt(user.email, user.iv_email, user.password);

      console.log("Decrypted email:", decryptedEmail);
      //quand sa a matche, il renvoie
      if (decryptedEmail === email) {
        console.log("Email match found:", user);
        return user;
      }
      return null;
    }).filter((user) => user !== null);
    //si il a pas trouvé, il le dit
    if (decryptedUsers.length > 0) {
      return decryptedUsers[0];
    } else {
      console.log("No user found with the email.");
    }
    return null; 
  } catch (error) {
    //erreur
    console.error("Error in findUserByEmail:", error);
    throw error; 
  }
};
