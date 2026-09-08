import Link from "next/link";
import type { ComponentProps } from "react";

import { Button } from "@/components/ui/button";

type ButtonProps = ComponentProps<typeof Button>;
type LinkProps = ComponentProps<typeof Link>;

interface ButtonLinkProps extends Omit<ButtonProps, "render" | "nativeButton"> {
  href: LinkProps["href"];
  prefetch?: LinkProps["prefetch"];
  target?: string;
  rel?: string;
}

/**
 * A button that navigates.
 *
 * Base UI's `Button` assumes it renders a native `<button>` (`nativeButton`
 * defaults to `true`). Rendering a Next.js `<Link>` produces an `<a>` instead,
 * which drops native button semantics and makes Base UI warn — so the flag has
 * to be turned off. Routing through this component keeps that detail in one
 * place instead of at every call site.
 */
export function ButtonLink({ href, prefetch, target, rel, ...props }: ButtonLinkProps) {
  return (
    <Button
      {...props}
      nativeButton={false}
      render={<Link href={href} prefetch={prefetch} target={target} rel={rel} />}
    />
  );
}
