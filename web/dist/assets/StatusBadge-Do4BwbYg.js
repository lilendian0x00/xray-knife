import{j as i}from"./react-BVkdo5-W.js";import{B as o}from"./badge-D5frm7Zk.js";import{c,u as t,L as m}from"./index-C-BaxllS.js";import{b as d,a as l,C as p}from"./circle-x-D2mzqL_O.js";/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const g=[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["line",{x1:"12",x2:"12",y1:"8",y2:"12",key:"1pkeuh"}],["line",{x1:"12",x2:"12.01",y1:"16",y2:"16",key:"4dfq90"}]],x=c("circle-alert",g);/**
 * @license lucide-react v0.525.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const f=[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["line",{x1:"9",x2:"15",y1:"15",y2:"9",key:"1dfufj"}]],y=c("circle-slash",f),b={passed:{variant:"pass",icon:p,label:"Passed"},"semi-passed":{variant:"semi",icon:x,label:"Semi-passed"},failed:{variant:"fail",icon:l,label:"Failed"},broken:{variant:"fail",icon:y,label:"Broken"},timeout:{variant:"fail",icon:l,label:"Timeout"},canceled:{variant:"neutral",icon:d,label:"Canceled"}};function C({status:e,compact:r}){const a=t(),n=b[e]??{variant:"neutral",icon:d,label:e},s=n.icon;return i.jsxs(o,{variant:n.variant,className:r?"gap-1 font-medium @max-lg:px-1":"gap-1 font-medium",title:a(n.label),children:[i.jsx(s,{"aria-hidden":!0}),i.jsx("span",{className:r?"@max-lg:sr-only":void 0,children:a(n.label)})]})}function S({state:e,label:r}){const a=t(),n=e==="starting"||e==="stopping",s=e==="running"?"pass":e==="error"?"fail":n?"info":"neutral",u=r??{idle:a("Idle"),stopped:a("Stopped"),starting:a("Starting"),stopping:a("Stopping"),running:a("Running"),error:a("Error")}[e];return i.jsxs(o,{variant:s,className:"gap-1.5",children:[n?i.jsx(m,{className:"animate-spin","aria-hidden":!0}):i.jsx("span",{"aria-hidden":!0,className:`size-1.5 rounded-full ${e==="running"?"bg-pass":e==="error"?"bg-fail":"bg-muted-foreground/60"}`}),u]})}export{C as R,S};
