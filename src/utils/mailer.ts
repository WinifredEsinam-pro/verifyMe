import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

export async function sendVerificationEmail(
  to: string,
  token: string
): Promise<void> {
  const verifyUrl = `${process.env.CLIENT_URL}/auth/verify-email?token=${token}`;

  await transporter.sendMail({
    from: `"VerifyMe" <${process.env.EMAIL_USER}>`,
    to,
    subject: "Verify your email address",
    html: `
      <div style="font-family: sans-serif; max-width: 480px; margin: auto;">
        <h2>Confirm your email</h2>
        <p>Thanks for signing up. Click the button below to verify your email address. This link expires in 1 hour.</p>
        <p>
          <a href="${verifyUrl}" style="display:inline-block;padding:10px 20px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px;">
            Verify Email
          </a>
        </p>
        <p>Or paste this link into your browser:</p>
        <p>${verifyUrl}</p>
      </div>
    `,
  });
}

export async function sendLoginOtpEmail(to: string, code: string): Promise<void> {
  await transporter.sendMail({
    from: `"VerifyMe" <${process.env.EMAIL_USER}>`,
    to,
    subject: "Your login verification code",
    html: `
      <div style="font-family: sans-serif; max-width: 480px; margin: auto;">
        <h2>Your login code</h2>
        <p>Enter this code to finish logging in. It expires in 10 minutes.</p>
        <p style="font-size: 32px; font-weight: bold; letter-spacing: 8px; background:#f4f6fb; padding: 16px 24px; border-radius: 8px; text-align: center;">
          ${code}
        </p>
        <p>If you didn't just try to log in, you can safely ignore this email.</p>
      </div>
    `,
  });
}
