import assert from "node:assert/strict";
import test from "node:test";
import { createReportsModel } from "../ui/bundle.js";
const deferred = () => { let resolve; const promise=new Promise(r=>{resolve=r;});return {promise,resolve}; };
const empty = {items:[],total:0,next_offset:0};

test("advisory filters and paging remain separate from finding queries",async()=>{
 const calls=[];const model=createReportsModel({async invokeAction(key,input){calls.push({key,...input});return empty;}});
 await model.setWorkspace("ws");await model.aggregate({...model.getSnapshot().aggregateQuery,tool:"OSV",offset:25});
 await model.setView("advisories");await model.advisories({...model.getSnapshot().advisoryQuery,severity:"high",tool:"Trivy",offset:25});
 await model.openAdvisory({key:"key",id:"CVE-2026-12345"});
 const members=calls.find(c=>c.key==="advisories.findings");assert.equal(members.body.severity,"");assert.equal(members.body.tool,"Trivy");
 model.backAdvisories();assert.equal(model.getSnapshot().advisoryQuery.offset,25);assert.equal(model.getSnapshot().advisoryQuery.severity,"high");
 assert.equal(model.getSnapshot().aggregateQuery.tool,"OSV");assert.equal(model.getSnapshot().aggregateQuery.offset,25);model.destroy();
});
test("deleting a report refreshes advisories and clears stale member data",async()=>{
 const calls=[];const model=createReportsModel({async invokeAction(key){calls.push(key);return empty;}});
 await model.setWorkspace("ws");await model.setView("advisories");await model.openAdvisory({key:"key"});await model.open("report");
 await model.remove("report");assert.equal(model.getSnapshot().selectedAdvisory,null);assert.equal(model.getSnapshot().advisoryFindings,null);assert.equal(calls.filter(key=>key==="advisories.list").length,2);model.destroy();
});
test("late advisory lists cannot publish after leaving the page",async()=>{
 const old=deferred();const model=createReportsModel({async invokeAction(key,input){return key==="advisories.list"?old.promise:empty;}});
 await model.setWorkspace("ws");const pending=model.setView("advisories");await model.setView("findings");old.resolve({items:[{id:"old"}]});await pending;
 assert.equal(model.getSnapshot().view,"findings");assert.equal(model.getSnapshot().advisories,null);assert.equal(model.getSnapshot().advisoryLoading,false);model.destroy();
});
test("advisory member selection, back navigation and workspace changes fence stale data",async()=>{
 const old=deferred(),late=deferred();const model=createReportsModel({async invokeAction(key,{body}){if(key==="advisories.findings"&&body.id==="old")return old.promise;if(key==="advisories.findings"&&body.id==="late")return late.promise;return empty;}});
 await model.setWorkspace("a");await model.setView("advisories");const first=model.openAdvisory({key:"old"});await model.openAdvisory({key:"new"});old.resolve({items:[{id:"wrong"}]});await first;
 assert.equal(model.getSnapshot().selectedAdvisory.key,"new");assert.deepEqual(model.getSnapshot().advisoryFindings,empty);
 const second=model.openAdvisory({key:"late"});model.backAdvisories();await model.setWorkspace("b");late.resolve({items:[{id:"wrong"}]});await second;
 assert.equal(model.getSnapshot().workspaceId,"b");assert.equal(model.getSnapshot().selectedAdvisory,null);assert.equal(model.getSnapshot().advisoryFindings,null);model.destroy();
});
