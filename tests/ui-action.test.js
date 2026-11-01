import assert from "node:assert/strict";
import test from "node:test";

let importCount = 0;

function element(type, props, ...children) {
  return { type, props: props || {}, children };
}

async function loadPlugin({ action, i18n = true }) {
  let pluginId;
  let definition;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      registerKandevPlugin(id, pluginDefinition) {
        pluginId = id;
        definition = pluginDefinition;
      },
    },
  });
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { platform: "Linux" },
  });

  await import(new URL(`../ui/bundle.js?action-test=${importCount++}`, import.meta.url));

  const components = [];
  const navigations = [];
  const navItems = [];
  const routes = [];
  const ui = {
    Button: "Button",
    Tooltip: "Tooltip",
    TooltipTrigger: "TooltipTrigger",
    TooltipContent: "TooltipContent",
  };
  if (action) ui.Action = action;

  const host = {
    jsx: element,
    React: {},
    ui,
    navigate(path) {
      navigations.push(path);
    },
  };
  if (i18n) {
    host.i18n = {
      useTranslation() {
        return {
          t(key, options) {
            return `localized:${key}:${options?.defaultValue || ""}`;
          },
        };
      },
    };
  }

  const registry = {
    registerNavItem(item) { navItems.push(item); },
    registerRoute(path) { routes.push(path); },
    registerWsHandler() {},
    registerComponent(slot, component) {
      components.push({ slot, component });
    },
  };
  definition.initialize(registry, host);
  return { pluginId, components, host, navigations, navItems, routes };
}

function findNodes(node, type) {
  if (!node || typeof node !== "object") return [];
  const current = node.type === type ? [node] : [];
  return current.concat(node.children.flatMap((child) => findNodes(child, type)));
}

function composerComponent(components) {
  const registrations = components.filter((entry) => entry.slot === "chat-input-actions");
  assert.equal(registrations.length, 1, "the composer slot keeps one registration");
  return registrations[0].component;
}

test("uses Action once when the host exports it", async () => {
  function Action() {}
  const loaded = await loadPlugin({ action: Action });
  const control = composerComponent(loaded.components)({ slotProps: { taskTitle: "Example task" } });

  assert.equal(loaded.pluginId, "kandev-security");
  assert.equal(loaded.navItems[0].label, "Security");
  assert.equal(loaded.navItems[0].path, "/security");
  assert.deepEqual(loaded.routes, ["/security", "/security/advisories"]);
  assert.equal(control.type, Action);
  assert.equal(control.props.id, "security-chat-action");
  assert.equal(control.props.label, "localized:openSecurityPage:Security: open page");
  assert.match(control.props.tooltip, /Example task/);
  assert.equal(findNodes(control, "Button").length, 0);
  control.props.onClick();
  assert.deepEqual(loaded.navigations, ["/security"]);
});

test("keeps one legacy Button path on a host without Action or i18n", async () => {
  const loaded = await loadPlugin({ action: null, i18n: false });
  const control = composerComponent(loaded.components)({ slotProps: { taskId: "task-123" } });
  const buttons = findNodes(control, "Button");

  assert.equal(loaded.pluginId, "kandev-security");
  assert.equal(loaded.navItems[0].label, "Security");
  assert.equal(loaded.navItems[0].path, "/security");
  assert.deepEqual(loaded.routes, ["/security", "/security/advisories"]);
  assert.equal(control.type, "Tooltip");
  assert.equal(buttons.length, 1);
  assert.equal(buttons[0].props.id, "security-chat-action");
  assert.match(buttons[0].props["aria-label"], /task-123/);
  assert.equal(findNodes(control, "Action").length, 0);
  buttons[0].props.onClick();
  assert.deepEqual(loaded.navigations, ["/security"]);
});
