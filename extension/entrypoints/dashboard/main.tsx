import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import "../../components/theme.css";
import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./dashboard.css";

const root = createRoot(document.getElementById("root")!);
root.render(<App />);
