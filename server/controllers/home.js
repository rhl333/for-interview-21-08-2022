import bookModel from "../model/bookSchema.js";
import authorModel from "../model/authorSchema.js";
export const home = async (req, res) => {
  // let allBooks = await bookModel.find().populate("author", "name");

  // return res.status(200).json({ books: allBooks });
  let allBooks = await bookModel.find()?.sort({ createdAt: -1 });

  let data = await Promise.all(
    allBooks.map(async (book) => {
      let authorId = book.author;
      let authorDetails = await authorModel.findById(authorId);
      return { title: book.title, price: book.price, pubDate: book.pubDate, author: authorDetails.name, _id: book._id };
    })
  );
  return res.json(data);
};
