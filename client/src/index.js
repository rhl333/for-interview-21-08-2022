import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "./index.css";
import { GlobalProvider } from "./context/GlobalContext";
import { AuthorProvider } from "./context/authorContext";
import App from "./App";

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(
  <React.StrictMode>
    <GlobalProvider>
      <AuthorProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AuthorProvider>
    </GlobalProvider>
  </React.StrictMode>
);
