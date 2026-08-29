import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { Foundation } from "./Foundation";
import "./styles.css";

const root = document.getElementById("root");

if (root === null) {
  throw new Error("Stead web root is missing");
}

createRoot(root).render(
  <StrictMode>
    <Foundation />
  </StrictMode>,
);
