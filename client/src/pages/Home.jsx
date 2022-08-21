import "./home.scss";
import axios from "axios";
import { useEffect } from "react";
import Form from "../components/Form/Form";
import { useContext } from "react";
import { authorContext } from "../context/authorContext";

const Home = () => {
  let { state, dispatch } = useContext(authorContext);
  const token = JSON.parse(localStorage.getItem("user")).token;
  async function handleDelete(_id) {
    try {
      let response = await axios.delete(`${process.env.REACT_APP_BACKEND_URL}/delete`, {
        data: { bookId: _id },
        headers: { Authorization: `Bearer ${token}` },
      });
      dispatch({ type: "DELETE", payload: response.data });
    } catch (error) {
      console.log(error);
    }
  }
  useEffect(() => {
    if (token) {
      const getData = async () => {
        try {
          let response = await axios.get(process.env.REACT_APP_BACKEND_URL, { headers: { Authorization: `Bearer ${token}` } });
          dispatch({ type: "FETCH", payload: response.data });
        } catch (error) {
          console.log(error);
        }
      };
      getData();
    }
  }, []);
  return (
    <div>
      <Form />
      <div className="homePage">
        <div className="homeContainer">
          <div className="thead">
            <h3>Title</h3>
            <h3>Author</h3>
            <h3>Price</h3>
            <h3>Published On</h3>
            {/* <p>Delete</p> */}
          </div>
          <div className="data">
            {state.data.map((book) => {
              return (
                <div className="tbody" key={book._id}>
                  <p>{book.title}</p>
                  <p>{book.author}</p>
                  <p>{book.price}</p>
                  <p>{book.pubDate}</p>
                  <div className="deletebtn">
                    <button onClick={() => handleDelete(book._id)}>Delete</button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Home;
