import "./navbar.scss";

import { Link, useNavigate } from "react-router-dom";
import { GlobalContext } from "../../context/GlobalContext";
import { useContext } from "react";

const Navbar = () => {
  let navigate = useNavigate();
  let { state, isLoggedIn, setIsLoggedIn } = useContext(GlobalContext);
  function handleLogOut() {
    localStorage.removeItem("user");
    setIsLoggedIn(() => false);
    navigate("/login");
    // document.location.reload();
  }
  return (
    <div className="navbar">
      <div className="navbarContainer">
        <Link to="/" className="logo">
          PSIBORG
        </Link>
        <div className="navLinks">
          {!isLoggedIn && <Link to="/login">Login</Link>}
          {!isLoggedIn && <Link to="register">Register</Link>}
          {isLoggedIn && (
            <div className="afterLogin">
              <span>{state?.userData?.email}</span>
              <button onClick={() => handleLogOut()}>Logout</button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Navbar;
