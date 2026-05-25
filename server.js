const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// temporary storage (no database)
let users = [];

// ================= SIGNUP =================
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  // check if user exists
  const userExists = users.find(u => u.email === email);
  if (userExists) return res.send("User already exists");

  // hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  // save user
  users.push({
    email,
    password: hashedPassword,
    role: "user"
  });

  res.send("User registered");
});

// ================= LOGIN =================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);
  if (!user) return res.send("User not found");

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.send("Wrong password");

  // create token
  const token = jwt.sign(
    { email: user.email, role: user.role },
    "secretkey",
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// ================= AUTH MIDDLEWARE =================
function auth(req, res, next) {
  const token = req.headers.authorization;

  if (!token) return res.send("No token");

  try {
    const decoded = jwt.verify(token, "secretkey");
    req.user = decoded;
    next();
  } catch {
    res.send("Invalid token");
  }
}

// ================= PROTECTED ROUTE =================
app.get("/dashboard", auth, (req, res) => {
  res.send("Welcome " + req.user.email);
});

// ================= ADMIN ROUTE =================
app.get("/admin", auth, (req, res) => {
  if (req.user.role !== "admin") {
    return res.send("Access denied");
  }
  res.send("Welcome Admin");
});

// ================= START SERVER =================
app.listen(5000, () => {
  console.log("Server running on http://localhost:5000");
});