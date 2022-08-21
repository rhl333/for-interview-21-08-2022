import { useState } from "react";
import { useReducer, createContext } from "react";

let initialState = { userData: JSON.parse(localStorage.getItem("user")) || null };

function globalReducer(state = initialState, action) {
  switch (action.type) {
    case "LOGIN":
      return { ...state, userData: action.payload };
    case "REGISTER":
      return { ...state, userData: action.payload };
    case "LOG_OUT":
      return { userData: null };
    default:
      return { state };
  }
}

export const GlobalContext = createContext();

export const GlobalProvider = ({ children }) => {
  const [isLoggedIn, setIsLoggedIn] = useState(() => (localStorage.getItem("user") ? true : false));
  const [state, dispatch] = useReducer(globalReducer, initialState);
  let values = {
    state: state,
    dispatch: dispatch,
    isLoggedIn: isLoggedIn,
    setIsLoggedIn: setIsLoggedIn,
  };

  return <GlobalContext.Provider value={values}>{children}</GlobalContext.Provider>;
};
