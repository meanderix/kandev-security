import assert from "node:assert/strict";
import test from "node:test";
import { createTaskLaunchModel } from "../ui/bundle.js";
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
const launch=(workspaceId)=>({workspace_id:workspaceId,issue_id:`issue-${workspaceId}`,preset_id:"fix",title:"Fix",description:"Evidence",workflow_id:"wf",default_step_id:"step",steps:[]});
test("task launch preparation fences a late workspace response",async()=>{
 const old=deferred();const calls=[];
 const model=createTaskLaunchModel({async invokeAction(key,input){calls.push({key,input});if(key==="task_presets.get")return {presets:[]};if(key==="tasks.prepare")return input.workspaceId==="a"?old.promise:launch("b");}});
 await model.setWorkspace("a");const pending=model.prepare({report_id:"source",ordinal:7},"fix");await model.setWorkspace("b");old.resolve(launch("a"));await pending;
 assert.equal(model.getSnapshot().launch,null);await model.prepare({report_id:"current",ordinal:2},"fix");assert.equal(model.getSnapshot().launch.workspaceId,"b");assert.deepEqual(calls.at(-1).input.body,{id:"current",ordinal:2,preset_id:"fix"});model.destroy();
});
test("failed association retries only linking, without recreating the native task",async()=>{
 let fail=true;const calls=[];
 const model=createTaskLaunchModel({async invokeAction(key,input){calls.push({key,input});if(key==="task_presets.get")return {presets:[]};if(key==="tasks.prepare")return launch(input.workspaceId);if(key==="tasks.link"&&fail)throw new Error("Network failure");if(key==="tasks.list")return {items:[{task_id:"task"}],total:1,next_offset:0};return {linked:true};}});
 await model.setWorkspace("a");await model.prepare({report_id:"r",ordinal:0},"fix");const prepared=model.getSnapshot().launch;model.closeLaunch();assert.equal(await model.completed(prepared,{id:"task"}),false);
 assert.equal(model.getSnapshot().pending.length,1);assert.equal(model.getSnapshot().pending[0].taskId,"task");fail=false;assert.equal(await model.retryLink("task"),true);assert.equal(model.getSnapshot().pending.length,0);assert.equal(calls.filter(c=>c.key==="tasks.prepare").length,1);assert.equal(calls.filter(c=>c.key==="tasks.link").length,2);assert.equal(model.getSnapshot().links["issue-a"].total,1);model.destroy();
});
test("late native creation records its original scope without leaking into another workspace",async()=>{
 const linked=deferred();const calls=[];
 const model=createTaskLaunchModel({async invokeAction(key,input){calls.push({key,input});if(key==="task_presets.get")return {presets:[]};if(key==="tasks.prepare")return launch(input.workspaceId);if(key==="tasks.link")return linked.promise;return {items:[],total:0,next_offset:0};}});
 await model.setWorkspace("a");await model.prepare({report_id:"r",ordinal:0},"fix");const prepared=model.getSnapshot().launch;await model.setWorkspace("b");const pending=model.completed(prepared,{id:"created"});assert.equal(model.getSnapshot().pending.length,0);assert.equal(calls.at(-1).input.workspaceId,"a");linked.resolve({linked:true});await pending;assert.equal(model.isCurrent(prepared),false);assert.deepEqual(model.getSnapshot().links,{});model.destroy();
});
test("task link read pages and late updates retain their issue and workspace",async()=>{
 const late=deferred();let waiting=false;
 const model=createTaskLaunchModel({async invokeAction(key,{body}){if(key==="task_presets.get")return {presets:[]};if(waiting)return late.promise;return {items:[{task_id:body.offset?"second":"first"}],total:2,next_offset:body.offset?0:25};}});
 await model.setWorkspace("a");await model.loadTasks("issue");await model.loadTasks("issue",25);assert.deepEqual(model.getSnapshot().links.issue.items.map(i=>i.task_id),["first","second"]);waiting=true;const pending=model.loadTasks("issue");waiting=false;await model.setWorkspace("b");late.resolve({items:[{task_id:"private"}],total:1,next_offset:0});await pending;assert.deepEqual(model.getSnapshot().links,{});model.destroy();
});
