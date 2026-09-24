import mongoose, { Schema, Document, Model } from "mongoose";
import bcrypt from "bcrypt";


export interface IUser extends Document {
  name: string;
  email: string;
  password: string;
  isVerified: boolean;
  verificationToken?: string;
  verificationTokenExpires?: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
}

const userSchema = new Schema<IUser>(
  {
    name: {
      type: String,
      required: [true, "Name is required"],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        "Please provide a valid email address",
      ],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters long"],
      select: false,
      validate: {
        validator: function (value: string) {
          const hasUpper = /[A-Z]/.test(value);
          const hasLower = /[a-z]/.test(value);
          const hasNumber = /[0-9]/.test(value);
          const hasSymbol = /[^A-Za-z0-9]/.test(value);
          return hasUpper && hasLower && hasNumber && hasSymbol;
        },
        message:
          "Password must include at least one uppercase letter, one lowercase letter, one number, and one symbol",
      },
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    verificationToken: {
      type: String,
    },
    verificationTokenExpires: {
      type: Date,
    },
  },
  { timestamps: true }
);


userSchema.pre("save", async function (this: IUser) {
  if (!this.isModified("password")) return;

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});


userSchema.methods.comparePassword = async function (
  candidatePassword: string
): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

export const User: Model<IUser> = mongoose.model<IUser>("User", userSchema);