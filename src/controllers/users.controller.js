import User from "../models/usermodel.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

// Generate access token
const generateAccessToken = (user) => {
  return jwt.sign({ email: user.email }, process.env.ACCESS_JWT_SECRET, {
    expiresIn: "6h",
  });
};

// Generate refresh token
const generateRefreshToken = (user) => {
  return jwt.sign({ email: user.email }, process.env.REFRESH_JWT_SECRET, {
    expiresIn: "7d",
  });
};

// Register user
const registerUser = async (req, res) => {
  const { email, password, fullName, userName } = req.body;

  if (!email || !password || !fullName || !userName) {
    return res.status(400).json({ message: "All fields are required" });
  }

  const user = await User.findOne({ email: email });
  if (user) return res.status(401).json({ message: "User already exists" });

  try {
    const createUser = await User.create({
      email,
      password,
      userName,
      fullName,
    });
    res.json({
      message: "User registered successfully",
      data: createUser,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error occurred while registering user" });
  }
};

// Login user
const loginUser = async (req, res) => {
  const { email, password } = req.body;

  if (!email) return res.status(400).json({ message: "Email required" });
  if (!password) return res.status(400).json({ message: "Password required" });

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "No user found" });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid)
    return res.status(400).json({ message: "Incorrect password" });

  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: false });

  res.json({
    message: "User logged in successfully",
    accessToken,
    refreshToken,
    data: user,
  });
};

// Logout user
const logoutUser = async (req, res) => {
  res.clearCookie("refreshToken");
  res.json({ message: "User logged out successfully" });
};

// Refresh token
const refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
  if (!refreshToken)
    return res.status(401).json({ message: "No refresh token found!" });

  try {
    const decodedToken = jwt.verify(
      refreshToken,
      process.env.REFRESH_JWT_SECRET
    );

    const user = await User.findOne({ email: decodedToken.email });
    if (!user) return res.status(404).json({ message: "Invalid token" });

    const newAccessToken = generateAccessToken(user);
    res.json({ message: "Access token generated", accessToken: newAccessToken });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error verifying refresh token" });
  }
};

export { registerUser, loginUser, logoutUser, refreshToken };
