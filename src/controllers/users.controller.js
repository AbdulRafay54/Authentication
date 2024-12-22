import Users from "../models/usermodel.js";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const saltRounds = 10;
const encryptPassword = (req, res) => {
  const { password } = req.body;
  bcrypt.hash(password, saltRounds, function (err, hash) {
    if (err) {
      res.status(400).json({
        message: "error is occuring while encrypting the password",
        err: err,
      });
    } else {
      console.log(hash);
      res.status(200).json({
        message: "encryption completed successfully",
        hash: hash,
      });
    }
  });
};

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

const registerUser = async (req, res) => {
  const { email, password } = req.body;
  const user = await Users.findOne({
    email: email,
  });
  if (user) {
    res.status(401).json({
      message: "User already exist",
    });
  } else {
    const createUser = Users.create({
      email,
      password,
    });
    res.status(200).json({
      message: "user added successfully",
    });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;
  const user = await Users.findOne({
    email: email,
  });
  if (!user) {
    res.status(400).json({
      message: "user not found",
    });
  }
  if (!email) {
    res.status(400).json({
      message: "email is required",
    });
  }
  if (!password) {
    res.status(400).json({
      message: "email is required",
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    res.status(400).json({
      message: "invalid passoword",
    });
  }

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
export {
  encryptPassword,
  generateAccessToken,
  generateRefreshToken,
  registerUser,
  loginUser,
};