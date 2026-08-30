import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { Foundation } from "./Foundation";
import { startBrowserPerformanceInstrumentation } from "./performance";
import "./styles.css";

const root = document.getElementById("root");

if (root === null) {
  throw new Error("Stead web root is missing");
}

startBrowserPerformanceInstrumentation();

createRoot(root).render(
  <StrictMode>
    <Foundation />
  </StrictMode>,
);
