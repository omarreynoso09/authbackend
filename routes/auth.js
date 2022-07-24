var express = require("express");
var router = express.Router();
const bcrypt = require("bcryptjs");
const { uuid } = require("uuidv4");
const { blogsDB } = require("../mongo");
const { MongoMissingCredentialsError } = require("mongodb");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
dotenv.config();

const createUser = async (username, passwordHash) => {
  const collection = await blogsDB().collection("users");
  const user = {
    username: username,
    password: passwordHash,
    uid: uuid(),
  };
  try {
    await collection.insertOne(user);
    return true;
  } catch (error) {
    console.error(e);
    return false;
  }
};

router.post("/register-user", async function (req, res, next) {
  try {
    const username = req.body.username;
    const password = req.body.password;
    const saltRounds = 5; // In a real application, this number would be somewhere between 5 and 10
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    const userSaveSuccess = await createUser(username, hash);
    res.status(200).json({ success: userSaveSuccess });
  } catch (e) {
    res
      .status(500)
      .json({ message: "Error registering user.", success: false });
  }
});

router.post("/login-user", async function (req, res, next) {
  const username = req.body.username;
  const password = req.body.password;
  const collection = await blogsDB().collection("users");
  try {
    const user = await collection.findOne({
      username: username,
    });
    if (!user) {
      res.json({ success: false }).status(204);
      return;
    }
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      const jwtSecretKey = process.env.JWT_SECRET_KEY;
      const data = {
        time: new Date(),
        userId: user.uid,
      };
      const token = jwt.sign(data, jwtSecretKey);
      res.status(200).json({ success: true, token });
      return;
    }
    res.json({ success: false });
  } catch (error) {
    res.status(500).json({ message: "Error logging in.", success: false });
  }
});

router.get("/validate-token", function (req, res) {
  const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
  const jwtSecretKey = process.env.JWT_SECRET_KEY;
  try {
    const token = req.header(tokenHeaderKey);
    const verified = jwt.verify(token, jwtSecretKey);
    if (verified) {
      return res.json({ success: true });
    } else {
      // Access Denied
      throw Error("Access Denied");
    }
  } catch (error) {
    // Access Denied
    return res.status(401).json({ success: true, message: String(error) });
  }
});

module.exports = router;
