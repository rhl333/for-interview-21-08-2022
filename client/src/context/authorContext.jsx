import { useReducer, createContext } from "react";

let initialState = { data: [] };

let reducerFunction = (state = initialState, action) => {
  // switch (action.type) {
  //   case "CREATED":
  //     return { ...state, data: action.payload.concat(state.data) };
  //   case "DELETED":
  //     return { ...state, data: state.data.filter((workout) => workout._id !== action.payload._id) };
  //   case "RECIEVED":
  //     return { ...state, data: action.payload };
  //   default:
  //     return state;
  // }

  switch (action.type) {
    case "FETCH":
      return { ...state, data: action.payload };
    case "CREATE":
      return { ...state, data: action.payload.concat(state.data) };
    case "DELETE":
      return { ...state, data: state.data.filter((book) => book._id !== action.payload._id) };

    default:
      return state;
  }
};

let authorContext = createContext();

let AuthorProvider = ({ children }) => {
  let [state, dispatch] = useReducer(reducerFunction, initialState);

  return <authorContext.Provider value={{ state: state, dispatch: dispatch }}>{children}</authorContext.Provider>;
};

export { authorContext, AuthorProvider };
