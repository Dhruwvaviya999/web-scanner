import { NextResponse, type NextRequest } from "next/server";

/**
 * First-pass routing based on the presence of the auth cookie.
 *
 * This is a redirect convenience, NOT a security boundary: the cookie is
 * httpOnly but its presence is not proof of a valid token. Every protected
 * resource is authorised by the FastAPI backend on each request.
 */
const AUTH_COOKIE_NAME = process.env.NEXT_PUBLIC_AUTH_COOKIE_NAME ?? "ws_access_token";

const PROTECTED_PREFIX = "/dashboard";
const GUEST_ONLY_PATHS = ["/login", "/register"];

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const hasSession = Boolean(request.cookies.get(AUTH_COOKIE_NAME)?.value);

  if (pathname.startsWith(PROTECTED_PREFIX) && !hasSession) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("next", `${pathname}${search}`);
    return NextResponse.redirect(loginUrl);
  }

  if (hasSession && GUEST_ONLY_PATHS.includes(pathname)) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*", "/login", "/register"],
};
