// Test-only host adapter. Browser tests exercise the real plugin bundle with
// React and mocked action transport; production Kandev is not started here.
import React from "react";
import { createRoot } from "react-dom/client";
import * as Popover from "@radix-ui/react-popover";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as Dialog from "@radix-ui/react-dialog";
let definition;
window.registerKandevPlugin = (_, plugin) => { definition = plugin; };
await import("../../ui/bundle.js");
let workspaceId = "ws-a";
const listeners = new Set();
const routes = new Map();
let Settings;
let settingsContributor;
const root = createRoot(document.getElementById("root"));
const Button = React.forwardRef(({ variant, size, className = "", ...props }, ref) => <button {...props} ref={ref} className={`host-button ${className}`} data-variant={variant} data-size={size} />);
const Input = React.forwardRef(({ className = "", ...props }, ref) => <input {...props} ref={ref} className={`host-input ${className}`} />);
const registry = { registerTranslations() {}, registerNavItem() {}, registerRoute(path, component, options) { routes.set(path,{Page:component,chrome:options.topbar}); }, registerComponent() {}, registerIntegrationSettings(value) { Settings=value.Component; } };
function TaskCreateDialog({open,onOpenChange,initialValues,workspaceId,workflowId,onSuccess}) {
  if(!open)return null;
  return <Dialog.Root open onOpenChange={onOpenChange}><Dialog.Portal><Dialog.Overlay style={{position:"fixed",inset:0,background:"#0008",zIndex:60}} /><Dialog.Content style={{position:"fixed",inset:"5vh 5vw",maxHeight:"90vh",overflow:"auto",background:"white",padding:24,zIndex:61}}>
    <Dialog.Title>Create security task</Dialog.Title><Dialog.Description>Native task creation host adapter</Dialog.Description>
    <form onSubmit={async(event)=>{event.preventDefault();const response=await fetch("/native-task",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({workspaceId,workflowId,title:event.target.elements.title.value,description:event.target.elements.description.value})});const task=await response.json();onOpenChange(false);await onSuccess(task,"create",{autoFocus:false});}}>
      <label>Task title<input name="title" defaultValue={initialValues.title}/></label><label>Task description<textarea name="description" rows={10} defaultValue={initialValues.description}/></label>
      <button type="submit">Start native task</button><button type="button" onClick={()=>onOpenChange(false)}>Cancel task</button>
    </form>
  </Dialog.Content></Dialog.Portal></Dialog.Root>;
}
const host = {
  React, jsx: React.createElement, navigate(href) {window.history.pushState({},"",href);window.dispatchEvent(new PopStateEvent("popstate"));}, ui: { Button, Input, TaskCreateDialog,
    Sheet: Dialog.Root, SheetTitle: Dialog.Title, SheetDescription: Dialog.Description,
    SheetContent: ({ children, side, showCloseButton, ...props }) => <Dialog.Portal><Dialog.Overlay style={{position:"fixed",inset:0,background:"#0008",zIndex:49}} /><Dialog.Content {...props}>{children}</Dialog.Content></Dialog.Portal>,
    Popover: Popover.Root, PopoverTrigger: Popover.Trigger,
    PopoverContent: ({ children, ...props }) => <Popover.Portal><Popover.Content sideOffset={4} {...props}>{children}</Popover.Content></Popover.Portal>,
    DropdownMenu: DropdownMenu.Root, DropdownMenuTrigger: DropdownMenu.Trigger,
    DropdownMenuContent: ({ children, className = "", ...props }) => <DropdownMenu.Portal><DropdownMenu.Content className={`host-menu ${className}`} sideOffset={4} {...props}>{children}</DropdownMenu.Content></DropdownMenu.Portal>,
    DropdownMenuItem: DropdownMenu.Item,
  },
  i18n: { useTranslation: () => ({ t: (key, options) => options.defaultValue?.replace(/\{\{(\w+)\}\}/g, (_, name) => String(options.values?.[name] ?? (name === "count" ? options.count : undefined) ?? "")) ?? key }) },
  api: { async invokeAction(key, input, { signal } = {}) {
    const response = await fetch(`/actions/${key}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input), signal });
    const value = await response.json(); if (!response.ok) throw new Error(value.error); return value;
  } },
  context: { getActiveWorkspaceId: () => workspaceId, subscribeActiveWorkspace(fn) { listeners.add(fn); return () => listeners.delete(fn); } },
};
if(new URLSearchParams(window.location.search).has("native-settings"))host.useSettingsSaveContributor=function(contributor){
  React.useEffect(()=>{
    settingsContributor=contributor;window.dispatchEvent(new Event("settings-contributor"));
    return ()=>{if(settingsContributor?.id===contributor.id){settingsContributor=undefined;window.dispatchEvent(new Event("settings-contributor"));}};
  },[contributor.id,contributor.revision,contributor.isDirty,contributor.canSave]);
};
definition.initialize(registry, host);
function App() {
  const [,renderSettings]=React.useState(0);
  React.useEffect(()=>{const update=()=>renderSettings(n=>n+1);window.addEventListener("settings-contributor",update);return ()=>window.removeEventListener("settings-contributor",update);},[]);
  const [path,setPath]=React.useState(window.location.pathname);
  const {Page,chrome}=routes.get(path)||routes.get("/security");
  const Actions=chrome.actions;
  const [activeWorkspace,setActiveWorkspace]=React.useState(workspaceId);
  React.useEffect(()=>{const update=()=>setPath(window.location.pathname);window.addEventListener("popstate",update);return ()=>window.removeEventListener("popstate",update);},[]);
  return <><button onClick={() => { workspaceId = workspaceId === "ws-a" ? "ws-b" : "ws-a"; listeners.forEach((fn) => fn(workspaceId));setActiveWorkspace(workspaceId); }}>Switch workspace</button>
    <header className="host-topbar"><h1>{chrome.title}</h1><Actions /></header>{settingsContributor?.isDirty?<button disabled={!settingsContributor.canSave} onClick={()=>{const c=settingsContributor;c.save(c.revision).catch(()=>{});}}>Native save presets</button>:null}{path.includes("/settings/")?<Settings workspaceId={activeWorkspace}/>:<Page />}</>;
}
root.render(<App />);
