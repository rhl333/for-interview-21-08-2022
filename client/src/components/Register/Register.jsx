import "./Register.scss";
import axios from "axios";

import { useFormik } from "formik";
import { useNavigate } from "react-router-dom";

import { GlobalContext } from "../../context/GlobalContext";
import { useContext } from "react";
import { useState } from "react";

const Register = () => {
  let navigate = useNavigate();
  let { dispatch, setIsLoggedIn } = useContext(GlobalContext);
  const [msg, setMsg] = useState(() => "");
  const [msgColor, setMsgColor] = useState(() => "");
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
        const response = await axios.post(`${process.env.REACT_APP_BACKEND_URL}/api/auth/register`, {
          email: currState.email.toLowerCase(),
          password: currState.password,
        });
        currState.email = "";
        currState.password = "";
        dispatch({ type: "REGISTER", payload: response.data });
        setIsLoggedIn(() => true);
        setMsg(() => response.data.msg);
        setMsgColor(() => "green");
        localStorage.setItem("user", JSON.stringify(response.data));
        setTimeout(() => navigate("/"), 2000);
      } catch (error) {
        setMsg(() => error?.response?.data?.msg);
        setMsgColor(() => "red");
      }
    },
  });
  return (
    <div className="registerForm">
      <div className="registerFormContainer">
        <h2>Register</h2>
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
          </div>
          <div className="submitBtn">
            <button type="submit">Register</button>
          </div>
        </form>
        <div className="msg">{msg && <p style={{ color: msgColor, marginTop: "1rem", fontSize: "0.9rem" }}>{msg}</p>}</div>
      </div>
    </div>
  );
};

export default Register;
