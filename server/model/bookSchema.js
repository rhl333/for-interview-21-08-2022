import mongoose from "mongoose";

let bookSchema = new mongoose.Schema(
  {
    title: { type: String, unique: true },
    price: String,
    pubDate: String,
    author: { type: mongoose.Schema.Types.ObjectId, ref: "Author" },
  },
  { timestamps: true }
);

export default mongoose.model("Book", bookSchema);
