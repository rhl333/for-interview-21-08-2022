import { Link } from "react-router-dom";

const ErrorPage = () => {
  return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "70vh" }}>
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", flexDirection: "column", rowGap: "0rem" }}>
        <h2 style={{ fontWeight: "bolder", fontSize: "5rem" }}>404</h2>
        <h3 style={{ fontSize: "2.5rem" }}>Page Not Found</h3>
        <Link
          to="/"
          style={{
            padding: "0.6rem 1.7rem",
            border: "3px solid orange",
            marginTop: "2rem",
            color: "blue",
            fontSize: "1.2rem",
            background: "white",
            borderRadius: "4px",
          }}
        >
          Go To Homepage
        </Link>
      </div>
    </div>
  );
};
export default ErrorPage;
