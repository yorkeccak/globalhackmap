"use client";

import dynamic from "next/dynamic";

// The markdown stack (streamdown, remark, rehype) is about a third of a page's JavaScript and only
// renders once an answer or report arrives, so it loads on demand. Call `loadStreamdown()` when the
// request starts, so the renderer is ready when the text lands.
export const loadStreamdown = () => import("streamdown").then((mod) => mod.Streamdown);
export const Streamdown = dynamic(loadStreamdown);
