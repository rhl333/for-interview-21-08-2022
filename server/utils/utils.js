export const generateRandomUsername = (email) => {
  let num1 = Math.floor(Math.random() * 568 + 1);
  let num2 = Math.floor(Math.random() * 26 + 1);
  let num3 = Math.floor(Math.random() * 900 + 1);
  let split = email.split("@");
  return split[0] + num1 + num2 + num3;
};
