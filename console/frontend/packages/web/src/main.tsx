import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { Overview } from "./pages/Overview";
import { AttackList } from "./pages/AttackList";
import { AttackDetail } from "./pages/AttackDetail";
import { FlowSearch } from "./pages/FlowSearch";
import "./styles.css";

const router = createBrowserRouter([
  {
    element: <AppShell />,
    children: [
      { path: "/", element: <Overview /> },
      { path: "/overview", element: <Overview /> },
      { path: "/flows", element: <FlowSearch /> }, // R6 明细查询（docs/10 §5.2）
      { path: "/security/attacks", element: <AttackList /> }, // R2 列表
      { path: "/security/attacks/:id", element: <AttackDetail /> }, // R5 详情
      { path: "/attacks/:id", element: <AttackDetail /> }, // 详情短链别名
    ],
  },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
