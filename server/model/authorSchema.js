import mongoose from "mongoose";
let authorSchema = new mongoose.Schema(
  {
    name: String,
    age: String,
    dob: String,
  },
  { timestamps: true }
);

export default mongoose.model("Author", authorSchema);
