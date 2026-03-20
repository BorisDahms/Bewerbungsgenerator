function base64UrlToBytes(input: string) {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

function base64UrlToString(input: string) {
  const bytes = base64UrlToBytes(input);
  return new TextDecoder().decode(bytes);
}

export async function verifyToken(token: string | null) {
  if (!token) {
    return false;
  }

  const secret = process.env.LINK_SIGNING_SECRET;
  if (!secret) {
    return false;
  }

  const parts = token.split(".");
  if (parts.length !== 2) {
    return false;
  }

  const [payloadEncoded, signatureEncoded] = parts;

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const isValidSignature = await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlToBytes(signatureEncoded),
      new TextEncoder().encode(payloadEncoded)
    );

    if (!isValidSignature) {
      return false;
    }

    const payloadText = base64UrlToString(payloadEncoded);
    const payload = JSON.parse(payloadText);

    if (payload.app !== "bewerbung") {
      return false;
    }

    if (typeof payload.exp !== "number") {
      return false;
    }

    if (Date.now() > payload.exp) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}
