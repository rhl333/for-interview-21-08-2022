import mongoose from "mongoose";
import authorModel from "../model/authorSchema.js";

import bookModel from "../model/bookSchema.js";

export const createData = async (req, res) => {
  let { authorName, authorAge, authorDob, bookTitle, bookPrice, bookPubDate } = req.body;
  if (!authorName || !authorAge || !authorDob || !bookPrice || !bookTitle || !bookPubDate) {
    return res.status(401).send("all the fields are required");
  }
  try {
    let author = await authorModel.findOne({ name: authorName });
    if (author) {
      let newBook = new bookModel({
        title: bookTitle,
        price: bookPrice,
        pubDate: bookPubDate,
        author: author._id,
      });
      await newBook.save();
      let { title, price, pubDate, _id } = newBook;
      let authorWas = await authorModel.findById(newBook.author, { name: 1 });
      // console.log({ title, price, pubDate, _id, author: authorWas?.name || "Default Name" });
      return res.status(200).json({ title, price, pubDate, _id, author: authorWas?.name || "Default Name" });
    } else {
      let newAuthor = new authorModel({
        name: authorName,
        age: authorAge,
        dob: authorDob,
      });
      await newAuthor.save();

      let newBook = new bookModel({
        title: bookTitle,
        price: bookPrice,
        pubDate: bookPubDate,
        author: newAuthor._id,
      });
      await newBook.save();

      const authorDetail = await authorModel.findById(newBook.author, { name: 1 });
      let { title, price, pubDate, _id } = newBook;
      // console.log("from ixisting", { title, _id, price, pubDate, author: authorDetail?.name });
      return res.status(200).json({ title, _id, price, pubDate, author: authorDetail?.name });
    }
  } catch (error) {
    if (error.code == 11000) return res.status(401).send("Duplicate book name. Please enter a unique name");
    return res.status(500).json({ error: error });
  }
};

export const deleteBook = async (req, res) => {
  let { bookId } = req.body;
  // console.log(req.body);
  // console.log(bookId);
  if (!bookId) return res.status(401).send("book id is required");
  if (!mongoose.Types.ObjectId.isValid(bookId)) return res.status(401).send("invalid book id");
  let book = await bookModel.findById(bookId);
  try {
    if (book) {
      await bookModel.deleteOne({ _id: bookId });
      return res.status(200).json(book);
    } else return res.status(404).send("this book does not exist");
  } catch (error) {
    console.log(error);
  }
};
