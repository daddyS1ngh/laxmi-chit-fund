const express = require("express");

const router = express.Router();
const {
  signup,
  verifyOtp,
  resendOtp,
  login,
  forgotPassword,
  resetPassword,
  updatePassword,
  protect,
} = require("../controller/user.controller");

router.route("/sign-up").post(signup);
router.route("/verify-otp").post(verifyOtp);
router.route("/resend-otp").post(resendOtp);
router.route("/login").post(login);
router.route("/forgot-password").post(forgotPassword);
router.route("/reset-password").post(resetPassword);
router.route("/update-password").post(protect, updatePassword);

module.exports = router;
