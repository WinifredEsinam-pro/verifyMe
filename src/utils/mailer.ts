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