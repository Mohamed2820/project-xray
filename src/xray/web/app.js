
(function(){
"use strict";
const $=function(selector){return document.querySelector(selector);};
const state={report:null,history:{scans:[],runtimes:[],repairs:[],tests:[]},runtime:null,selectedFile:null};
const titles={dashboard:"لوحة معلومات المشروع",files:"مستكشف الملفات",graph:"خريطة العلاقات الشاملة",flows:"خريطة تدفق البيانات",errors:"سجل الأخطاء",deps:"مكتبة الاعتماديات والأدوات",security:"مركز الأمان والأسرار",changes:"سجل التغييرات",runtime:"تتبع التنفيذ والقرارات"};
function arr(value){return Array.isArray(value)?value:[];}
function obj(value){return value&&typeof value==="object"&&!Array.isArray(value)?value:{};}
function fmt(value){return value===null||value===undefined||value===""?"—":String(value);}
function number(value){return Number.isFinite(Number(value))?Number(value).toLocaleString("en-US"):"0";}
function make(tag,className,value){const item=document.createElement(tag);if(className)item.className=className;if(value!==undefined)item.textContent=fmt(value);return item;}
function clear(node){while(node.firstChild)node.removeChild(node.firstChild);}
function empty(node,message){clear(node);const box=make("div","empty");box.appendChild(make("strong","",message));box.appendChild(make("span","", "ستظهر البيانات هنا بعد توفر نتيجة الفحص أو السجل المناسب."));node.appendChild(box);}
function pill(value,kind){return make("span","pill "+(kind||""),value);}
function statusName(status){const map={analyzed:"تم التحليل",inventory_only:"فهرسة فقط",analysis_error:"خطأ تحليل",inventoried:"تمت الفهرسة",skipped_size_limit:"تجاوز حد الحجم",skipped_total_size_limit:"تجاوز الحد الإجمالي",changed_or_unsafe_file:"ملف غير آمن/متغير",complete:"مكتمل",partial:"جزئي",success:"نجاح",failed:"فشل",baseline_created:"خط أساس جديد",compared:"تمت المقارنة",history_not_configured:"السجل غير مفعّل",awaiting_snapshot_comparison:"بانتظار المقارنة"};return map[status]||fmt(status);}
function severityKind(sev){return sev==="critical"||sev==="high"?"bad":sev==="medium"?"warn":"good";}
function levelName(sev){return ({critical:"حرج",high:"عالٍ",medium:"متوسط",low:"منخفض",info:"معلومة"})[sev]||fmt(sev);}
function report(){return obj(state.report);}
function analyses(){return obj(report().analyses);}
function findings(){return arr(report().findings);}
function dataFlows(){return arr(obj(analyses().data_flows).items);}
function runtimeOfReport(){return obj(analyses().runtime);}
function setNotice(message,show){const n=$("#notice");n.textContent=message;n.classList.toggle("show",!!show);}
function addKV(parent,label,value,code){const row=make("div","detail-kv");row.appendChild(make("span","",label));row.appendChild(make("span",code?"code":"",value));parent.appendChild(row);}
function addMetric(parent,label,value,foot){const card=make("div","card");card.appendChild(make("div","metric-label",label));card.appendChild(make("div","metric-value",value));card.appendChild(make("div","metric-foot",foot||""));parent.appendChild(card);}
async function fetchJSON(path){const response=await fetch(path,{method:"GET",cache:"no-store",headers:{"Accept":"application/json"}});if(!response.ok){let message="HTTP "+response.status;try{const data=await response.json();message=data.error||message;}catch(_e){}throw new Error(message);}return response.json();}
async function refresh(){
 $("#connection").textContent="جارٍ التحديث";$("#connection").className="pill";
 try{
  const results=await Promise.allSettled([fetchJSON("/api/report"),fetchJSON("/api/history"),fetchJSON("/api/health")]);
  if(results[1].status==="fulfilled")state.history=obj(results[1].value);
  if(results[0].status==="fulfilled")state.report=results[0].value;else state.report=null;
  $("#connection").textContent=results[2].status==="fulfilled"?"متصل · محلي":"بيانات محلية";$("#connection").className="pill good";
  if(!state.report)setNotice("الخادم يعمل، لكن لا يوجد تقرير مسح متاح. نفّذ xray scan مع قاعدة بيانات خارج مجلد المشروع ثم حدّث الصفحة.",true);
  else setNotice("تم تحميل تقرير المسح بنجاح. بيانات التشغيل تظهر بعد تنفيذ trace-python وتسجيل جلسته.",false);
  renderAll();
 }catch(error){$("#connection").textContent="غير متصل";$("#connection").className="pill bad";setNotice("تعذر تحميل بيانات اللوحة: "+error.message,true);}
}
function renderAll(){const r=report();$("#projectPath").textContent=fmt(r.root);$("#projectPath").title=fmt(r.root);renderDashboard();renderFiles();renderGraph();renderFlows();renderErrors();renderDependencies();renderSecurity();renderChanges();renderRuntime();}
function renderDashboard(){
 const r=report(),cov=obj(r.coverage),sev={critical:0,high:0,medium:0,low:0};
 findings().forEach(function(f){const s=String(f.severity||"low").toLowerCase();sev[s]=(sev[s]||0)+1;});
 $("#mFiles").textContent=number(arr(r.files).length);$("#mNodes").textContent=number(arr(r.nodes).length);$("#mEdges").textContent=number(arr(r.edges).length);$("#mFindings").textContent=number(findings().length);
 const max=Math.max(1,...Object.values(sev)),bars=$("#severityBars");clear(bars);
 [["حرج",sev.critical],["عالٍ",sev.high],["متوسط",sev.medium],["منخفض",sev.low]].forEach(function(entry){const row=make("div","bar-row");row.appendChild(make("span","",entry[0]));const bar=make("div","bar"),fill=make("span");fill.style.width=(entry[1]/max*100)+"%";bar.appendChild(fill);row.appendChild(bar);row.appendChild(make("b","",entry[1]));bars.appendChild(row);});
 const coverage=$("#coverage");clear(coverage);const complete=cov.scan_complete===true;coverage.appendChild(pill(complete?"اكتمل الفحص":"الفحص جزئي أو غير مكتمل",complete?"good":"warn"));
 [["حالة الفهرسة",statusName(cov.filesystem_inventory)],["الملفات المفحوصة",cov.files_seen],["الملفات التي حُللت",cov.analyzed_files],["الزمن المستغرق",fmt(cov.elapsed_seconds)+" ثانية"],["حد التوقف",cov.scan_limit_reached||"لم يُسجّل"],["تنفيذ كود المشروع",cov.code_execution===true?"نعم":"لا"],["اتصال شبكي أثناء المسح",cov.network_access===true?"نعم":"لا"]].forEach(function(pair){addKV(coverage,pair[0],pair[1],false);});
 renderRecent($("#recentScans"),arr(state.history.scans).slice(0,4),"scan");renderRecent($("#recentRuntime"),arr(state.history.runtimes).slice(0,4),"runtime");
}
function renderRecent(container,items,kind){
 clear(container);if(!items.length){empty(container,"لا توجد سجلات بعد");return;}
 items.forEach(function(item){const box=make("div","item");const title=kind==="scan"?"مسح "+fmt(item.scan_id).slice(0,12):fmt(item.script);box.appendChild(make("h4","",title));box.appendChild(make("p","",fmt(item.created_at||item.started_at)+" · "+statusName(item.status||"saved")));box.appendChild(make("p","",kind==="scan"?fmt(item.file_count)+" ملف · "+fmt(item.finding_count)+" نتيجة":"رمز الخروج: "+fmt(item.exit_code)));
  if(kind==="runtime"){const btn=make("button","btn secondary","فتح الجلسة");btn.type="button";btn.addEventListener("click",function(){loadRuntime(item.session_id);});box.appendChild(btn);}container.appendChild(box);});
}
function renderFiles(){
 const files=arr(report().files),search=$("#fileSearch").value.trim().toLowerCase(),status=$("#fileStatus").value,selected=state.selectedFile;
 const filtered=files.filter(function(file){const match=fmt(file.path).toLowerCase().includes(search),stat=fmt(file.status);const statusMatch=!status||(status==="skipped"?stat.startsWith("skipped")||stat==="changed_or_unsafe_file":stat===status);return match&&statusMatch;});
 $("#fileCount").textContent=number(filtered.length)+" من "+number(files.length)+" ملف";
 const list=$("#fileList");clear(list);if(!filtered.length)empty(list,"لا توجد ملفات مطابقة");else filtered.slice(0,1000).forEach(function(file){const btn=make("button","file-item"+(selected===file.path?" selected":""));btn.type="button";btn.appendChild(make("strong","",file.path));btn.appendChild(make("small","",statusName(file.status)+" · "+fmt(file.language)+" · "+number(file.size_bytes)+" بايت"));btn.addEventListener("click",function(){state.selectedFile=file.path;renderFiles();});list.appendChild(btn);});
 const detail=$("#fileDetail");clear(detail);const file=files.find(function(item){return item.path===state.selectedFile;})||filtered[0];if(!file){detail.textContent="اختر ملفًا من القائمة لعرض تفاصيله.";return;}state.selectedFile=file.path;
 const related=arr(report().nodes).filter(function(n){return n.path===file.path;}),evidence=findings().filter(function(f){return obj(f.evidence).path===file.path;});
 detail.appendChild(make("h4","code",file.path));detail.appendChild(pill(statusName(file.status),file.status==="analyzed"?"good":file.status==="analysis_error"?"bad":""));
 addKV(detail,"اللغة · Language",file.language);addKV(detail,"الحجم · Size",number(file.size_bytes)+" بايت");addKV(detail,"SHA-256",file.sha256||"غير متاح",true);addKV(detail,"المحللات · Analyzers",arr(file.analyzers).join(", ")||"لا يوجد");addKV(detail,"العُقد المرتبطة",related.length);addKV(detail,"النتائج المرتبطة",evidence.length);
 if(arr(file.analysis_errors).length)detail.appendChild(make("p","red small","أخطاء المحللات: "+file.analysis_errors.map(function(e){return e.plugin+" ("+e.error+")";}).join("، ")));
 if(evidence.length){detail.appendChild(make("h4","panel-title","نتائج الفحص في هذا الملف"));evidence.forEach(function(f){const box=make("div","item");box.appendChild(make("strong","",f.rule_id+" · "+levelName(f.severity)));box.appendChild(make("p","",f.message));box.appendChild(make("p","code","السطر "+fmt(obj(f.evidence).line)));detail.appendChild(box);});}
}
function renderGraph(){
 const nodes=arr(report().nodes),edges=arr(report().edges),search=$("#graphSearch").value.trim().toLowerCase(),kind=$("#graphKind").value;$("#graphCount").textContent=number(nodes.length)+" عقدة · "+number(edges.length)+" علاقة";
 const selected=nodes.filter(function(n){return (!kind||n.kind===kind)&&(!search||(fmt(n.name).toLowerCase().includes(search)||fmt(n.path).toLowerCase().includes(search)));}).slice(0,140);
 const svg=$("#graphSvg");clear(svg);const ns="http://www.w3.org/2000/svg",width=900,cols=8,cellW=108,cellH=90,rows=Math.max(1,Math.ceil(selected.length/cols)),height=Math.max(560,rows*cellH+70);svg.setAttribute("viewBox","0 0 "+width+" "+height);
 const defs=document.createElementNS(ns,"defs"),marker=document.createElementNS(ns,"marker");marker.setAttribute("id","arrow");marker.setAttribute("markerWidth","7");marker.setAttribute("markerHeight","7");marker.setAttribute("refX","6");marker.setAttribute("refY","3");marker.setAttribute("orient","auto");const arrow=document.createElementNS(ns,"path");arrow.setAttribute("d","M0,0 L6,3 L0,6 Z");arrow.setAttribute("fill","#55718f");marker.appendChild(arrow);defs.appendChild(marker);svg.appendChild(defs);
 const positions=new Map();selected.forEach(function(n,i){positions.set(n.id,{x:55+(i%cols)*cellW,y:38+Math.floor(i/cols)*cellH});});
 edges.slice(0,260).forEach(function(e){const a=positions.get(e.source),b=positions.get(e.target);if(!a||!b)return;const line=document.createElementNS(ns,"line");line.setAttribute("x1",a.x);line.setAttribute("y1",a.y+12);line.setAttribute("x2",b.x);line.setAttribute("y2",b.y-10);line.setAttribute("stroke","#55718f");line.setAttribute("stroke-width","1.2");line.setAttribute("opacity",".5");line.setAttribute("marker-end","url(#arrow)");svg.appendChild(line);});
 selected.forEach(function(n){const p=positions.get(n.id),group=document.createElementNS(ns,"g");group.setAttribute("role","button");group.setAttribute("tabindex","0");group.style.cursor="pointer";const circle=document.createElementNS(ns,"circle");circle.setAttribute("cx",p.x);circle.setAttribute("cy",p.y);circle.setAttribute("r","18");const color=n.kind==="file"?"#70b7ff":n.kind==="function"?"#7ce0c3":n.kind==="dependency"?"#f3c66d":"#b8a4ff";circle.setAttribute("fill",color);circle.setAttribute("stroke","#071323");circle.setAttribute("stroke-width","3");group.appendChild(circle);
  const label=document.createElementNS(ns,"text");label.setAttribute("x",p.x);label.setAttribute("y",p.y+36);label.setAttribute("fill","#dbe7f8");label.setAttribute("font-size","10");label.setAttribute("text-anchor","middle");label.textContent=fmt(n.name).slice(0,17);group.appendChild(label);const title=document.createElementNS(ns,"title");title.textContent=fmt(n.kind)+" · "+fmt(n.name)+" · "+fmt(n.path);group.appendChild(title);
  const show=function(){const panel=$("#nodeDetail");clear(panel);panel.appendChild(make("h4","",n.name));addKV(panel,"النوع · Kind",n.kind);addKV(panel,"المسار · Path",n.path,true);addKV(panel,"السطر · Line",n.line);addKV(panel,"المعرّف · ID",n.id,true);};group.addEventListener("click",show);group.addEventListener("keydown",function(event){if(event.key==="Enter"||event.key===" "){event.preventDefault();show();}});svg.appendChild(group);});
 if(!selected.length){const t=document.createElementNS(ns,"text");t.setAttribute("x","450");t.setAttribute("y","270");t.setAttribute("text-anchor","middle");t.setAttribute("fill","#91a2bd");t.textContent="لا توجد عقد مطابقة";svg.appendChild(t);}
}
function renderFlows(){
 const items=dataFlows();$("#flowCount").textContent=number(items.length)+" مسار";const list=$("#flowList");clear(list);if(!items.length){empty(list,"لم يتم رصد تدفقات بيانات محتملة");return;}
 items.forEach(function(flow,index){
  const box=make("div","item"),top=make("div","item-top");
  top.appendChild(make("h4","","مسار بيانات "+(index+1)));top.appendChild(pill(fmt(flow.sink_type),"warn"));box.appendChild(top);
  const path=make("div","flow-path"),source=make("div","flow-node source"),sink=make("div","flow-node sink");
  source.appendChild(make("small","","المصدر · Source"));source.appendChild(make("strong","code",fmt(flow.source_path)+":"+fmt(flow.source_line)));
  sink.appendChild(make("small","","العملية الحساسة · Sink"));sink.appendChild(make("strong","code",fmt(flow.sink_expression)+" · "+fmt(flow.sink_line)));
  path.appendChild(source);path.appendChild(make("span","flow-arrow","←"));path.appendChild(sink);box.appendChild(path);
  box.appendChild(make("p","", "الدالة: "+fmt(flow.function)+" · مستوى الثقة: "+fmt(flow.confidence)));
  list.appendChild(box);
 });
}
function getRuntimeEvents(){const r=state.runtime||runtimeOfReport(),timeline=obj(r.timeline);return arr(timeline.events).length?arr(timeline.events):arr(r.events);}
function renderErrors(){
 const sessions=arr(state.history.runtimes),events=getRuntimeEvents(),errors=events.filter(function(e){return e.event_type==="exception"||e.event_type==="runtime_monitor_error";}),summary=$("#errorSummary");clear(summary);
 addMetric(summary,"جلسات التنفيذ",sessions.length,"المحفوظة في قاعدة البيانات");addMetric(summary,"أحداث الأخطاء",errors.length,"في الجلسة المحددة حاليًا");addMetric(summary,"جلسات فاشلة",sessions.filter(function(s){return s.status==="failed";}).length,"حسب exit status");
 renderRecent($("#errorList"),sessions.slice(0,50),"runtime");const output=$("#errorEvents");clear(output);if(!errors.length){empty(output,"لا توجد أخطاء مسجلة في الجلسة المعروضة");return;}
 errors.forEach(function(e){const box=make("div","item");box.appendChild(make("h4","red",fmt(e.exception_type||e.event_type)));box.appendChild(make("p","",fmt(e.detail||e.message||"لم تتوفر تفاصيل إضافية.")));box.appendChild(make("p","code",fmt(e.path)+(e.line?":"+e.line:"")+" · "+fmt(e.timestamp_utc)));output.appendChild(box);});
}
function renderDependencies(){
 const coverage=obj(report().coverage),plugins=arr(coverage.registered_analyzers),toolList=$("#toolList");clear(toolList);
 plugins.forEach(function(name){
  const box=make("div","item"),top=make("div","item-top");
  top.appendChild(make("h4","",fmt(name)));top.appendChild(pill("Plugin مسجل","good"));
  box.appendChild(top);
  box.appendChild(make("p","","محلل مضاف إلى Plugin Registry. أنواع الملفات التي يدعمه المحلل تظهر ضمن تفاصيل كل ملف."));
  toolList.appendChild(box);
 });
 const analyzers=[
  ["Dependency Analyzer","تحليل الحزم والاعتماديات",coverage.dependency_analysis],
  ["Permission Analyzer","استخراج مؤشرات الصلاحيات",coverage.permission_analysis],
  ["Data Flow Analyzer","تتبع المصدر إلى العملية الحساسة",coverage.data_flow_analysis],
  ["ADR Analyzer","فهرسة قرارات التصميم الموثقة",coverage.decision_analysis]
 ];
 analyzers.forEach(function(item){
  const box=make("div","item"),top=make("div","item-top");
  top.appendChild(make("h4","",item[0]+" · "+item[1]));
  top.appendChild(pill(statusName(item[2]),item[2]==="analyzed"?"good":item[2]==="partial"?"warn":""));
  box.appendChild(top);toolList.appendChild(box);
 });
 const runtime=make("div","item"),runtimeTop=make("div","item-top");
 const runtimeRecorded=Boolean(coverage.runtime&&coverage.runtime!=="not_collected");
 runtimeTop.appendChild(make("h4","","Python Runtime Adapter · مراقب التنفيذ"));
 runtimeTop.appendChild(pill(!coverage.runtime?"غير متاح":coverage.runtime==="not_collected"?"لا يعمل أثناء الفحص الساكن":"تم تسجيل حالة تشغيل",runtimeRecorded?"good":"warn"));
 runtime.appendChild(runtimeTop);
 runtime.appendChild(make("p","","يعمل فقط عند طلب trace-python بشكل صريح، ولا يبدأ تنفيذ البرامج تلقائيًا من لوحة المعلومات."));
 toolList.appendChild(runtime);
 if(!plugins.length&&!analyzers.length)empty(toolList,"لا تتوفر بيانات أدوات التحليل في التقرير الحالي");
 const items=arr(obj(analyses().dependencies).items),search=$("#depSearch").value.trim().toLowerCase();
 $("#depCount").textContent=number(items.length)+" اعتماد";const list=$("#depList");clear(list);
 const filtered=items.filter(function(d){return (fmt(d.name).toLowerCase()+" "+fmt(d.ecosystem).toLowerCase()).includes(search);});
 if(!filtered.length){empty(list,"لا توجد اعتماديات مطابقة");return;}
 filtered.slice(0,1000).forEach(function(d){const box=make("div","item"),top=make("div","item-top");top.appendChild(make("h4","code",fmt(d.name)));top.appendChild(pill(String(d.direct)==="true"?"مباشر · Direct":"انتقالي · Transitive",String(d.direct)==="true"?"good":""));box.appendChild(top);box.appendChild(make("p","",fmt(d.ecosystem)+" · الإصدار: "+fmt(d.version||d.requested||"غير محدد")));box.appendChild(make("p","", "المصدر: "+fmt(d.source||d.source_path)+" · المخاطر: "+arr(d.risk_flags).join("، ")+" · تنبيهات OSV: "+arr(d.advisory_ids).join(", ")));list.appendChild(box);});
}
function renderSecurity(){
 const all=findings().slice().sort(function(a,b){const rank={critical:4,high:3,medium:2,low:1};return (rank[b.severity]||0)-(rank[a.severity]||0);}),summary=$("#securitySummary");clear(summary);
 const secrets=all.filter(function(f){return fmt(f.rule_id).includes("secret")||fmt(f.rule_id).includes("token")||fmt(f.rule_id).includes("credential");});
 addMetric(summary,"كل النتائج",all.length,"نتائج الفحص الحالية");addMetric(summary,"أسرار محتملة",secrets.length,"القيم المكتشفة محجوبة");addMetric(summary,"نتائج عالية/حرجة",all.filter(function(f){return f.severity==="high"||f.severity==="critical";}).length,"بحسب تصنيف المحلل");
 const wanted=$("#securitySeverity").value,filtered=all.filter(function(f){return !wanted||f.severity===wanted;});$("#securityCount").textContent=number(filtered.length)+" نتيجة";const list=$("#securityList");clear(list);
 if(!filtered.length){empty(list,"لا توجد نتائج ضمن هذا الاختيار");return;}
 filtered.forEach(function(f){const box=make("div","item"),top=make("div","item-top");top.appendChild(make("h4","",f.rule_id));top.appendChild(pill(levelName(f.severity),severityKind(f.severity)));box.appendChild(top);box.appendChild(make("p","",f.message));const ev=obj(f.evidence);box.appendChild(make("p","code",fmt(ev.path)+(ev.line?":"+ev.line:"")));box.appendChild(make("p","muted small",fmt(ev.detail)));list.appendChild(box);});
}
function renderSimpleHistory(container,items,kind){
 clear(container);if(!items.length){empty(container,"لا توجد سجلات");return;}items.forEach(function(item){const box=make("div","item");box.appendChild(make("h4","",kind==="repair"?fmt(item.outcome):"Exit "+fmt(item.exit_code)));box.appendChild(make("p","",kind==="repair"?fmt(item.summary):fmt(item.summary||item.command)));box.appendChild(make("p","",fmt(item.created_at)));container.appendChild(box);});
}
function renderChanges(){
 const changes=obj(analyses().changes),added=arr(changes.added),modified=arr(changes.modified),deleted=arr(changes.deleted),summary=$("#changeSummary");clear(summary);addMetric(summary,"ملفات مضافة",added.length,"Added");addMetric(summary,"ملفات معدّلة",modified.length,"Modified");addMetric(summary,"ملفات محذوفة",deleted.length,"Deleted");
 const list=$("#changeList");clear(list);if(!["compared","baseline_created"].includes(changes.status))empty(list,statusName(changes.status||"غير متاح"));else if(changes.status==="baseline_created")empty(list,"تم إنشاء خط أساس؛ ستظهر الفروقات بعد المسح التالي.");else if(!added.length&&!modified.length&&!deleted.length)empty(list,"لا توجد تغييرات بين اللقطتين");else{
  [["مضاف",added],["معدّل",modified],["محذوف",deleted]].forEach(function(group){group[1].forEach(function(item){const box=make("div","item");box.appendChild(make("h4","",group[0]+" · "+fmt(item.path)));box.appendChild(make("p","", "بصمة سابقة: "+fmt(item.previous_sha256)+" · بصمة حالية: "+fmt(item.sha256)));list.appendChild(box);});});
 }
 renderSimpleHistory($("#repairs"),arr(state.history.repairs),"repair");renderSimpleHistory($("#tests"),arr(state.history.tests),"test");
}
function renderRuntime(){
 const timeline=$("#timeline");clear(timeline);const events=getRuntimeEvents();if(!events.length)empty(timeline,"لا توجد أحداث تشغيل مسجلة");else events.slice(0,500).forEach(function(e){const row=make("div","event");row.appendChild(make("span","event-dot"));const content=make("div","");content.appendChild(make("h4","",fmt(e.event_type)+" · "+fmt(e.function||e.detail||"")));content.appendChild(make("p","",fmt(e.timestamp_utc)+" · "+fmt(e.path)+(e.line?":"+e.line:"")));row.appendChild(content);timeline.appendChild(row);});
 const decisions=arr(obj(analyses().engineering_decisions).items),list=$("#decisions");clear(list);if(!decisions.length){empty(list,"لم يتم العثور على مستندات ADR معروفة");return;}
 decisions.forEach(function(d){const box=make("div","item");box.appendChild(make("h4","",fmt(d.title)));box.appendChild(pill(d.complete?"قرار موثق":"قرار غير مكتمل",d.complete?"good":"warn"));box.appendChild(make("p","code",fmt(d.path)));if(d.context)box.appendChild(make("p","", "السياق: "+d.context));if(d.decision)box.appendChild(make("p","", "القرار: "+d.decision));if(d.consequences)box.appendChild(make("p","", "النتائج: "+d.consequences));list.appendChild(box);});
}
async function loadRuntime(sessionId){
 try{state.runtime=await fetchJSON("/api/runtime/"+encodeURIComponent(sessionId));renderErrors();renderRuntime();setNotice("تم تحميل جلسة التنفيذ "+sessionId,false);switchPage("runtime");}
 catch(error){setNotice("تعذر تحميل جلسة التنفيذ: "+error.message,true);}
}
function switchPage(name){document.querySelectorAll(".page").forEach(function(p){p.classList.toggle("active",p.id===name);});document.querySelectorAll(".nav button").forEach(function(b){b.classList.toggle("active",b.dataset.page===name);});$("#pageTitle").textContent=titles[name]||"Project X-Ray";}
document.querySelectorAll(".nav button").forEach(function(button){button.addEventListener("click",function(){switchPage(button.dataset.page);});});
$("#refresh").addEventListener("click",refresh);$("#fileSearch").addEventListener("input",renderFiles);$("#fileStatus").addEventListener("change",renderFiles);$("#graphSearch").addEventListener("input",renderGraph);$("#graphKind").addEventListener("change",renderGraph);$("#depSearch").addEventListener("input",renderDependencies);$("#securitySeverity").addEventListener("change",renderSecurity);
refresh();
})();
