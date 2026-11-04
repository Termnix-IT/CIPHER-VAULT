import React from "react";
import ReactDOM from "react-dom/client";
import { App } from "./App";
import { applyDesignMode, readDesignMode } from "./lib/design-mode";
import "./styles.css";

// Applied before the first render so the saved design never flashes the default one.
applyDesignMode(readDesignMode());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
