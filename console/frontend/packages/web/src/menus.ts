/**
 * 菜单树（docs/10 §5.2：路由与菜单解耦，唯一维护处；路由 kebab-case，菜单中文，
 * 权限码 <domain>:<action>）。M1 仅注册已实现页面；其余项保留待 M2/M3 落地。
 */
export interface MenuItem {
  key: string;
  label: string; // 菜单显示中文（docs/10 §5.1 命名规则）
  path: string;
  perm: string; // 权限码（docs/11 §8）
  children?: MenuItem[];
}

export const MENUS: MenuItem[] = [
  { key: "overview", label: "总览", path: "/overview", perm: "overview:read" },
  {
    key: "security",
    label: "安全中心",
    path: "/security",
    perm: "attack:read",
    children: [
      { key: "attacks", label: "攻击中心", path: "/security/attacks", perm: "attack:read" },
      // TODO(M2/M3)：检测策略 policy:read/edit、处置联动 attack:handle（LucidBGP iframe）
    ],
  },
];

/** 当前登录态持有权限码（M1：dev token 的 perms claim；生产由 /api/v1/auth/* 下发）。 */
export function hasPerm(perms: string[] | null, perm: string): boolean {
  if (!perms) return false;
  return perms.includes(perm);
}
