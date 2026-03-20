export function verifyToken(token: string | null) {
  const validToken = process.env.ACCESS_TOKEN;

  if (!validToken) {
    return false;
  }

  if (!token) {
    return false;
  }

  return token === validToken;
}
