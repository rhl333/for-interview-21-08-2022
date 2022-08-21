import axios from "axios";
import { useFormik } from "formik";
import { useState, useContext } from "react";
import { GlobalContext } from "../../context/GlobalContext";
import { useNavigate } from "react-router-dom";
import "./Login.scss";
const Login = () => {
  let navigate = useNavigate();
  let { dispatch, setIsLoggedIn } = useContext(GlobalContext);
  const [errMsg, setErrMsg] = useState(() => "");
  const formik = useFormik({
    initialValues: {
      email: "",
      password: "",
    },
    validate: (currState) => {
      const errors = {};
      if (!currState.email) errors.email = "Email is required*";
      if (!currState.password) errors.password = "Password is required*";
      else if (currState.password.length < 5) errors.password = "Password must be greater than 5 characters.";
      return errors;
    },
    onSubmit: async (currState) => {
      try {
        const response = await axios.post(`${process.env.REACT_APP_BACKEND_URL}/api/auth/login`, {
          email: currState.email.toLowerCase(),
          password: currState.password,
        });
        localStorage.setItem("user", JSON.stringify(response.data));
        setIsLoggedIn(() => true);
        dispatch({ type: "LOGIN", payload: response.data });
        navigate("/");
      } catch (error) {
        setErrMsg(() => error?.response?.data?.msg);
      }
    },
  });
  return (
    <div className="form">
      <div className="formContainer">
        <h2>Login</h2>
        <form action="" onSubmit={formik.handleSubmit}>
          <div className="email">
            <label htmlFor="email">Email</label>
            <input type="email" name="email" value={formik.values.email} onChange={formik.handleChange} onBlur={formik.handleBlur} />
            <p>{formik.errors.email && formik.touched.email ? formik.errors.email : ""}</p>
          </div>
          <div className="password">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              name="password"
              autoComplete="on"
              value={formik.values.password}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
            />
            <p>{formik.errors.password && formik.touched.password ? formik.errors.password : ""}</p>
            {errMsg && <p style={{ marginTop: "0.8rem", fontSize: "0.9rem", textTransform: "capitalize" }}>{errMsg}</p>}
          </div>
          <div className="submitBtn">
            <button type="submit">Login</button>
          </div>
          {/* <div className="forget">
            <Link to="/forgotpassword">Forgot Password?</Link>
          </div> */}
          {/* <div className="createNew">
            <Link to="/register">Create New Account</Link>
          </div> */}
        </form>
      </div>
    </div>
  );
};

export default Login;
