/**
 * 菜单树（docs/10 §5.2：路由与菜单解耦，唯一维护处；路由 kebab-case，菜单中文，
 * 权限码 <domain>:<action>（docs/11 §8 白名单），图标 lucid-icons 域前缀 kebab）。
 * M2 第一批注册：总览 / 明细查询（R6）/ 攻击中心（R2 列表 + /:id 详情路由同权限码）；
 * 其余项保留待后续批次落地。
 */
export interface MenuItem {
  key: string;
  label: string; // 菜单显示中文（docs/10 §5.1 命名规则：一级 ≤4 字，二级 ≤6 字）
  path: string;
  perm: string; // 权限码（docs/11 §8：domain ∈ overview|flows|attack|…，action ∈ read|export|handle|…）
  /** lucid-icons 图标名（域前缀 kebab-case，docs/10 §2.3；sprite 接入前仅作登记）。 */
  icon?: string;
  children?: MenuItem[];
}

export const MENUS: MenuItem[] = [
  { key: "overview", label: "总览", path: "/overview", perm: "overview:read", icon: "sys-cluster" },
  {
    key: "flows",
    label: "明细查询",
    path: "/flows",
    perm: "flows:query", // 导出按钮另需 flows:export（页面内按 hasPerm 显隐/放行）
    icon: "flow-stream",
  },
  {
    key: "security",
    label: "安全中心",
    path: "/security",
    perm: "attack:read",
    icon: "sec-attack",
    children: [
      { key: "attacks", label: "攻击中心", path: "/security/attacks", perm: "attack:read", icon: "sec-attack" },
      // 详情页路由 /security/attacks/:id（兼容别名 /attacks/:id）不进菜单（docs/10 §5.2）
      // TODO(M2/M3)：检测策略 policy:read/edit、处置联动 attack:handle（LucidBGP iframe）
    ],
  },
];

/** 当前登录态持有权限码（M1：dev token 的 perms claim；生产由 /api/v1/auth/* 下发）。 */
export function hasPerm(perms: string[] | null, perm: string): boolean {
  if (!perms) return false;
  return perms.includes(perm);
}
