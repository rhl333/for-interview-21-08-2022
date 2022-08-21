import { Route, Routes } from "react-router-dom";
import { useContext } from "react";
import { GlobalContext } from "./context/GlobalContext";
import Login from "./components/Login/Login";
import Navbar from "./components/Navbar/Navbar";
import Register from "./components/Register/Register";
import ErrorPage from "./pages/ErrorPage";
import Home from "./pages/Home";
function App() {
  let { state } = useContext(GlobalContext);
  return (
    <div className="App">
      <Navbar />
      <Routes>
        <Route index element={state.userData ? <Home /> : <Login />} />
        <Route path="/login" element={localStorage.getItem("user") ? <Home /> : <Login />} />
        <Route path="/register" element={localStorage.getItem("user") ? <Home /> : <Register />} />
        <Route path="*" element={<ErrorPage />} />
      </Routes>
    </div>
  );
}

export default App;
