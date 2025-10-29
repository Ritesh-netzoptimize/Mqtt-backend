import { Router } from "express";
import { signup, login, getRefreshToken } from "../controllers/AuthController.js";

const authRoutes = Router();

authRoutes.post("/signup", signup);
authRoutes.post("/login", login);
authRoutes.post("/refresh-token", getRefreshToken);

export default authRoutes;