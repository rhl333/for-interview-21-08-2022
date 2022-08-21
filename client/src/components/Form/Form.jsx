import "./form.scss";
import { useState } from "react";
import axios from "axios";
import { useContext } from "react";
import { authorContext } from "../../context/authorContext";

const Form = () => {
  let [msg, setMsg] = useState(() => "");
  const token = JSON.parse(localStorage.getItem("user")).token;
  let { dispatch } = useContext(authorContext);
  let [values, setValues] = useState(() => ({
    authorName: "",
    authorAge: "",
    authorDOB: "",
    bookTitle: "",
    bookPrice: "",
    bookPublishedOn: "",
  }));
  async function handleSubmit(e) {
    e.preventDefault();
    try {
      let response = await axios.post(
        `${process.env.REACT_APP_BACKEND_URL}/create`,
        {
          authorName: values.authorName,
          authorAge: values.authorAge,
          authorDob: values.authorDOB,
          bookTitle: values.bookTitle.toLowerCase(),
          bookPrice: values.bookPrice,
          bookPubDate: values.bookPublishedOn,
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      dispatch({ type: "CREATE", payload: [response.data] });
      console.log(response.data);
      setMsg(() => "");
      setValues(() => ({ authorAge: "", authorDOB: "", authorName: "", bookPrice: "", bookPublishedOn: "", bookTitle: "" }));
    } catch (error) {
      setMsg(() => error?.response?.data);
      console.log(error);
    }
  }
  return (
    <div className="HomeForm">
      <div className="formContainer">
        <p className="abs">Autor's Date of Birth</p>
        <p className="abs">Book Published On</p>
        <h2>Enter New Book</h2>
        <form action="" onSubmit={(e) => handleSubmit(e)}>
          <div className="author">
            <input
              type="text"
              name="authorName"
              placeholder="Author Name"
              required
              value={values.authorName}
              onChange={(e) => setValues((prev) => ({ ...prev, authorName: e.target.value }))}
            />

            <input
              type="number"
              placeholder="Author's Age"
              name="authorAge"
              required
              value={values.authorAge}
              onChange={(e) => setValues((prev) => ({ ...prev, authorAge: e.target.value }))}
            />

            <input
              type="date"
              name="authorDOB"
              placeholder="Author's DOB : dd-mm-yy"
              required
              value={values.authorDOB}
              onChange={(e) => setValues((prev) => ({ ...prev, authorDOB: e.target.value }))}
            />
          </div>
          <div className="book">
            <input
              type="text"
              name="bookTitle"
              placeholder="Book Title"
              required
              value={values.bookTitle}
              onChange={(e) => setValues((prev) => ({ ...prev, bookTitle: e.target.value }))}
            />

            <input
              type="number"
              name="bookprice"
              placeholder="Book Price"
              required
              value={values.bookPrice}
              onChange={(e) => setValues((prev) => ({ ...prev, bookPrice: e.target.value }))}
            />

            <input
              type="date"
              name="bookPublishedOn"
              placeholder="Book Publish Date : dd-mm-yy"
              required
              value={values.bookPublishedOn}
              onChange={(e) => setValues((prev) => ({ ...prev, bookPublishedOn: e.target.value }))}
            />
          </div>
          <p className="data">{msg && msg}</p>
          <div className="btn">
            <button type="submit">Submit</button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Form;
