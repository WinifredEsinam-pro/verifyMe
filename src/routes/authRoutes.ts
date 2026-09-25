import { Router } from "express";
import { register, verifyEmail, login, verifyOtp, resendOtp, getProfile, resendVerification, logout } from "../controllers/authController.js";
import { requireAuth } from "../middleware/authMiddleware.js";

const router = Router();

router.post("/register", register);
router.get("/verify-email", verifyEmail);
router.post("/login", login);
router.post("/verify-otp", verifyOtp);
router.post("/resend-otp", resendOtp);
router.get("/me", requireAuth, getProfile);
router.post("/resend-verification", resendVerification);
router.post("/logout", requireAuth, logout);

export default router;