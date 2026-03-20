export function verifyToken(token: string | null) {
  if (!token) {
    return false;
  }

  return true;
}
