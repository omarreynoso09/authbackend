var express = require("express");
var router = express.Router();
const bcrypt = require("bcryptjs");
const { uuid } = require("uuidv4");
const { blogsDB } = require("../mongo");

const createUser = async (username, passwordHash) => {
  try {
    const collection = await blogsDB().collection("users");
    const user = {
      username,
      password: passwordHash,
      uid: uuid(),
    };

    await collection.insertOne(user);
    return true;
  } catch (e) {
    console.error(e);
    return false;
  }
};

router.post("/register-user", async function (req, res, next) {
  try {
    const username = req.body.username;
    const password = req.body.password;
    const saltRounds = 5;
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    const userSaveSuccess = await createUser(username, hash);
    res.json({ success: userSaveSuccess });
  } catch (e) {
    res.json({ success: false });
  }
});

router.post("/login-user", async function (req, res, next) {
  try {
    const collection = await blogsDB().collection("users");
    const user = await collection.findOne({ username: req.body.username });
    const match = await bcrypt.compare(req.body.password, user.password);
    res.json({ success: match });
  } catch (e) {
    console.error(e);
    res.json({ success: false });
  }
});

module.exports = router;
