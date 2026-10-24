/** 应用骨架（docs/10 §3.4：左侧导航 224px + 页头 48px；菜单树见 menus.ts）。 */
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { getToken, setToken, parsePerms } from "../api/client";
import { MENUS, hasPerm } from "../menus";

export function AppShell() {
  const [tok, setTok] = useState(getToken());
  const perms = parsePerms(tok);

  return (
    <div className="shell">
      <nav className="sidebar">
        <div className="brand">LucidNet</div>
        {MENUS.map((m) =>
          hasPerm(perms, m.perm) === false && perms.length > 0 ? null : (
            <div key={m.key}>
              {m.children ? (
                <>
                  <div style={{ padding: "8px 12px", color: "var(--lucid-neutral)", fontSize: 12 }}>
                    {m.label}
                  </div>
                  {m.children
                    .filter((c) => perms.length === 0 || hasPerm(perms, c.perm))
                    .map((c) => (
                      <NavLink key={c.key} to={c.path} className={({ isActive }) => (isActive ? "active" : "")}>
                        {c.label}
                      </NavLink>
                    ))}
                </>
              ) : (
                <NavLink to={m.path} className={({ isActive }) => (isActive ? "active" : "")}>
                  {m.label}
                </NavLink>
              )}
            </div>
          ),
        )}
      </nav>
      <div className="main">
        <header className="header">
          <strong>LucidNet 控制台</strong>
          <span style={{ color: "var(--lucid-neutral)", fontSize: 13 }}>M1-MVP</span>
          <div style={{ flex: 1 }} />
          <input
            aria-label="访问令牌"
            placeholder="粘贴访问令牌（lucid-gateway -dev-token）"
            defaultValue={tok}
            onChange={(e) => setTok(e.target.value)}
            onBlur={(e) => {
              setToken(e.target.value);
              location.reload();
            }}
            style={{ width: 320 }}
          />
        </header>
        <Outlet />
      </div>
    </div>
  );
}
