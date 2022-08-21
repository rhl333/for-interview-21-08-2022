import jwt from "jsonwebtoken";
const authHome = (req, res, next) => {
  const { authorization } = req.headers;
  // console.log(req.body);
  if (!authorization) return res.status(400).send("you are not authorized");

  const token = authorization.split(" ")[1];
  if (!token) return res.status(400).send("you are not authorized");

  let isVerified = jwt.verify(token, process.env.JWT_SECRET) ? true : false;
  if (isVerified) next();
};

export default authHome;
