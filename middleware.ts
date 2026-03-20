import { NextRequest, NextResponse } from "next/server";
import { verifyToken } from "./lib/verifyToken";

export function middleware(req: NextRequest) {
  const tokenFromUrl = req.nextUrl.searchParams.get("token");
  const tokenFromCookie = req.cookies.get("access_token")?.value ?? null;

  if (verifyToken(tokenFromUrl)) {
    const cleanUrl = req.nextUrl.clone();
    cleanUrl.searchParams.delete("token");

    const response = NextResponse.redirect(cleanUrl);
    response.cookies.set("access_token", tokenFromUrl as string, {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      path: "/",
    });

    return response;
  }

  if (verifyToken(tokenFromCookie)) {
    return NextResponse.next();
  }

  return new NextResponse("Nicht autorisiert", { status: 401 });
}

export const config = {
  matcher: ["/", "/generator.html"],
};
