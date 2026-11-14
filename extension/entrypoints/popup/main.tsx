import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "../../components/theme.css";
import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./popup.css";

const root = createRoot(document.body);
root.render(<App />);
