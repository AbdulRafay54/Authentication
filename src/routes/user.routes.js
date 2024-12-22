
import express from "express";
import {
  encryptPassword,
  generateRefreshToken,
  generateAccessToken,
  registerUser,
  loginUser,
} from "../controllers/users.controller.js";
const router = express.Router();
router.post("/encryptPassword", encryptPassword);
router.post("/refreshToken", generateRefreshToken);
router.post("/accessToken", generateAccessToken);
router.post("/register", registerUser);
router.post("/loginUser", loginUser);
export default router;
