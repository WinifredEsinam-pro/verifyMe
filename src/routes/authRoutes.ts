import { Router } from "express";
import { register, verifyEmail, login } from "../controllers/authController.js";

const router = Router();

router.post("/register", register);
router.get("/verify-email", verifyEmail);
router.post("/login", login);

export default router;