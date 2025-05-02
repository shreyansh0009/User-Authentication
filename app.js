const express = require("express");
const path = require("path");
const userModel = require("./models/user");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");

// Middleware to protect routes
function isLoggedIn(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  jwt.verify(token, "saurabh", async (err, decoded) => {
    if (err) {
      res.clearCookie('token');
      return res.redirect('/login');
    }

    const user = await userModel.findOne({ email: decoded.email });
    if (!user) {
      res.clearCookie('token');
      return res.redirect('/login');
    }

    req.user = user;
    next();
  });
}

// Show homepage (signup)
app.get("/", (req, res) => {
  if (req.cookies.token) return res.redirect('/userHome');
  res.render("index");
});

// Handle signup
app.post("/create", (req, res) => {
  const { username, email, password } = req.body;

  bcrypt.genSalt(10, (err, salt) => {
    if (err) return res.status(500).send("Error generating salt");

    bcrypt.hash(password, salt, async (err, hash) => {
      try {
        await userModel.create({
          username,
          email,
          password: hash,
        });

        const token = jwt.sign({ email }, "saurabh");
        res.cookie("token", token);
        res.redirect("/userHome");

      } catch (err) {
        if (err.code === 11000 && err.keyPattern.email) {
          // Email already exists
          return res.status(400).send("Email already exists. Try logging in instead.");
        }
        console.error("Signup error:", err);
        res.status(500).send("Something went wrong while creating user.");
      }
    });
  });
});

// Show login page
app.get("/login", (req, res) => {
  if (req.cookies.token) return res.redirect('/userHome');
  res.render("login");
});

// Handle login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await userModel.findOne({ email });

  if (!user) return res.status(400).send("Invalid email or password");

  bcrypt.compare(password, user.password, (err, result) => {
    if (err) return res.status(500).send("Error");
    if (result) {
      const token = jwt.sign({ email: user.email }, "saurabh");
      res.cookie("token", token);
      res.redirect("/userHome");
    } else {
      res.status(400).send("Invalid credentials");
    }
  });
});

// Protected user homepage
app.get("/userHome", isLoggedIn, (req, res) => {
  res.render("userHome", { user: req.user });
});

// Handle logout
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

app.listen(3000);
