import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    username: {
      type: "String",
      required: true,
    },
    email: {
      type: "String",
      required: true,
      unique: true,
    },
    password: {
      type: "String",
      required: true,
      select: false, // whenever we retrieve any user, it will not send the password field by default, until we specify explicitly.
      minLength: 6,
    },
    resetPasswordToken: "String",
    resetPasswordExpire: Date,
  },
  { timestamps: true }
);

export default mongoose.model("User", userSchema);
