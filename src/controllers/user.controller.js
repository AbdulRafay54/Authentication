import User from "../models/usermodel.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const generateAccessToken = (user) => {
  return jwt.sign({ email: user.email }, process.env.ACCESS_JWT_SECRET, {
    expiresIn: "6h",
  });
};
const generateRefreshToken = (user) => {
  return jwt.sign({ email: user.email }, process.env.REFRESH_JWT_SECRET, {
    expiresIn: "7d",
  });
};

// register user

const registerUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email) return res.status(400).json({ message: "email required" });
  if (!password) return res.status(400).json({ message: "password required" });

  const user = await User.findOne({ email: email });
  if (user) return res.status(401).json({ message: "user already exist" });

  const createUser = await User.create({
    email,
    password,
  });
  res.json({ message: "user registered successfully", data: createUser });
};

// login user

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email) return res.status(400).json({ message: "email required" });
  if (!password) return res.status(400).json({ message: "password required" });
  // email mujood ha bhi ya nahi ha
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "no user found" });
  // password compare krwayenga bcrypt
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid)
    return res.status(400).json({ message: "incorrect password" });

  // token generate
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  // cookies
  res.cookie("refreshToken", refreshToken, { http: true, secure: false });

  res.json({
    message: "user loggedIn successfully",
    accessToken,
    refreshToken,
    data: user,
  });
};

// logout user
const logoutUser = async (req, res) => {
  res.clearCookie("refreshToken");
  res.json({ message: "user logout successfully" });
};

// refreshtoken
const refreshToken = async (req, res) => {
  try {
    // Get the refresh token
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "No refresh token found!" }); 
    }

    // Verify the refresh token
    const decodedToken = jwt.verify(refreshToken, process.env.REFRESH_JWT_SECRET);

    // Find the user
    const user = await User.findOne({ email: decodedToken.email });
    if (!user) {
      return res.status(404).json({ message: "Invalid token" }); 
    }

    const generateToken = generateAccessToken(user);

    return res.json({
      message: "Access token generated",
      accesstoken: generateToken,
      decodedToken,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server Error", error: error.message });
  }
};


// authenticate user middleware
const authenticateUser = async (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(404).json({ message: "no token found" });

  jwt.verify(token, process.env.ACCESS_JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "invalid token" });
    req.user = user;
    next();
  });
};

export { registerUser, loginUser, logoutUser, refreshToken, authenticateUser };