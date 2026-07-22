// build_ppt.js — 答辩 PPT 生成脚本
// 前 22 页：封面 + 核心成绩 + Phase 1（每页一个概念，看着就能念）
// 后 26 页：Phase 2 + Phase 3 + 消融 + 局限性 + 总结

const pptxgen = require("pptxgenjs");
const path = require("path");
const fs = require("fs");

const C = {
  primary:"0F1A2E",secondary:"1A3550",accent:"2980B9",
  warning:"E67E22",danger:"C0392B",success:"27AE60",
  bg:"F4F6F8",white:"FFFFFF",text:"1A1A2E",
  muted:"6B7C93",cardBg:"FFFFFF",border:"E1E5EB",
};
const QL='“',QR='”';
function q(t){return QL+t+QR;}

const pres = new pptxgen();
pres.layout = "LAYOUT_16x9";
pres.author="Code Audit Team";
pres.title="基于大语言模型的应用安全审计技术";

const SS=path.join(__dirname,"screenshots");
function ss(n){return path.join(SS,n);}
function img(s,f,x,y,w,h){
  try{s.addImage({path:ss(f),x:x,y:y,w:w,h:h,sizing:{type:"contain",w:w,h:h}});}
  catch(e){s.addText("[截图未找到: "+f+"]",{x:x,y:y+h/2-0.2,w:w,h:0.4,fontSize:12,color:C.muted,fontFace:"Arial",align:"center"});}
}

// ── helpers ──
function secSlide(num,title,sub){
  const s=pres.addSlide();s.background={fill:C.primary};
  s.addText(num,{x:0.7,y:1.2,w:1.2,h:0.7,fontSize:14,color:C.accent,fontFace:"Arial",bold:true});
  s.addText(title,{x:0.7,y:2.0,w:8.6,h:1.8,fontSize:34,color:C.white,fontFace:"Cambria",bold:true,lineSpacingMultiple:1.15});
  if(sub)s.addText(sub,{x:0.7,y:3.6,w:8,h:0.5,fontSize:13,color:C.muted,fontFace:"Arial"});
  return s;
}
function cSlide(title){
  const s=pres.addSlide();s.background={fill:C.bg};
  s.addText(title,{x:0.7,y:0.35,w:8.6,h:0.65,fontSize:26,color:C.text,fontFace:"Cambria",bold:true});
  s.addShape(pres.shapes.RECTANGLE,{x:0.7,y:0.95,w:0.7,h:0.035,fill:{color:C.accent}});
  return s;
}
function scSlide(title,imgFile,caption){
  const s=cSlide(title);
  img(s,imgFile,0.7,1.2,8.6,3.5);
  if(caption)s.addText(caption,{x:0.7,y:4.85,w:8.6,h:0.3,fontSize:10,color:C.muted,fontFace:"Arial",align:"center"});
  return s;
}
function bigNum(s,x,y,w,h,num,label,color){
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x,y,w,h,fill:{color:C.cardBg},shadow:{type:"outer",blur:4,offset:2,color:"000000",opacity:0.06},rectRadius:0.08});
  s.addText(String(num),{x,y:y+0.05,w,h:h*0.55,fontSize:30,color:color||C.accent,fontFace:"Arial",bold:true,align:"center"});
  s.addText(label,{x:x+0.05,y:y+h*0.58,w:w-0.1,h:h*0.38,fontSize:10,color:C.muted,fontFace:"Arial",align:"center",lineSpacingMultiple:1.1});
}
function bl(s,x,y,w,h,items,opts){
  opts=opts||{};
  const arr=items.map(function(it,i){
    const last=i===items.length-1;
    if(typeof it==="string")return{text:it,options:{fontSize:opts.fs||14,color:opts.color||C.text,fontFace:"Arial",bullet:{color:opts.bc||C.accent},breakLine:!last,paraSpaceAfter:opts.gap||8}};
    return{text:it.text,options:{fontSize:opts.fs||14,color:it.color||C.text,fontFace:"Arial",bullet:it.bullet!==false?{color:opts.bc||C.accent}:false,bold:it.bold,breakLine:!last,paraSpaceAfter:opts.gap||8}};
  });
  s.addText(arr,{x:x,y:y,w:w,h:h,valign:"top",lineSpacingMultiple:1.35});
}
function bigBl(s,x,y,w,h,items,color){
  bl(s,x,y,w,h,items,{fs:16,gap:12,bc:color||C.accent});
}
function card(s,x,y,w,h,title,desc,color){
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x,y,w,h,fill:{color:C.cardBg},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.06});
  s.addShape(pres.shapes.RECTANGLE,{x,y,w:0.05,h,fill:{color:color||C.accent}});
  s.addText(title,{x:x+0.18,y:y+0.06,w:w-0.3,h:0.3,fontSize:13,color:color||C.text,fontFace:"Arial",bold:true});
  s.addText(desc,{x:x+0.18,y:y+0.38,w:w-0.3,h:h-0.46,fontSize:10,color:C.muted,fontFace:"Arial",lineSpacingMultiple:1.2});
}
function tbl(s,x,y,w,headers,rows){
  const hdr=headers.map(function(h){return{text:h,options:{fontSize:9,color:C.white,fontFace:"Arial",bold:true,fill:{color:C.secondary},align:"center",valign:"middle"}};});
  const data=rows.map(function(row,ri){return row.map(function(cell,ci){return{text:String(cell),options:{fontSize:9,color:ci===1?C.accent:C.text,fontFace:"Arial",bold:ci===1,fill:{color:ri%2===0?C.cardBg:C.bg},align:ci===0?"left":"center",valign:"middle"}};});});
  s.addTable([hdr].concat(data),{x:x,y:y,w:w,border:{type:"solid",color:C.border,pt:0.5},rowH:[0.3].concat(Array(rows.length).fill(0.28))});
}
function highlightBox(s,x,y,w,h,text,color){
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x,y,w,h,fill:{color:color||"FFF8E1"},rectRadius:0.06});
  s.addText(text,{x:x+0.15,y:y+0.05,w:w-0.3,h:h-0.1,fontSize:13,color:C.warning,fontFace:"Arial",bold:true,lineSpacingMultiple:1.2});
}

// ════════════════════════════════════════════
// SECTION A: 封面 + 核心成绩 + Phase 1 (22 slides)
// ════════════════════════════════════════════

// 1. Title
(function(){
  const s=pres.addSlide();s.background={fill:C.primary};
  s.addText("基于大语言模型的\n应用安全审计技术",{x:0.7,y:1.0,w:8.6,h:2.2,fontSize:38,color:C.white,fontFace:"Cambria",bold:true,lineSpacingMultiple:1.15});
  s.addText("LLM-Driven Application Security Audit",{x:0.7,y:3.1,w:8,h:0.5,fontSize:14,color:C.accent,fontFace:"Arial"});
  s.addShape(pres.shapes.RECTANGLE,{x:0.7,y:3.7,w:1.0,h:0.035,fill:{color:C.warning}});
  s.addText("零样本 · 无微调 · 静态分析 + LLM 多 Agent 协同",{x:0.7,y:3.9,w:8,h:0.4,fontSize:12,color:C.muted,fontFace:"Arial"});
})();

// 2. Outline
(function(){
  const s=cSlide("汇报提纲");
  const items=[
    {text:"一、核心成绩与学术对比 — PrimeVul F1=0.77，零样本超越微调基线",color:C.accent},
    {text:"二、Phase 1：起点 — Sink 注册表过拟合与四个优化层的失效",color:C.danger},
    {text:"三、Phase 2：模块化 — LLM 层层杀 TP 与静态拦截问题",color:C.warning},
    {text:"四、Phase 3：V4 三级 Agent + 工具感知链 — 架构重建",color:C.success},
    {text:"五、消融实验 — 控制变量法拆解每个组件的贡献",color:C.accent},
    {text:"六、局限性与坦诚讨论",color:C.muted},
  ];
  bl(s,0.7,1.4,8.6,3.5,items,{fs:15,gap:14,bc:C.accent});
})();

// ─── 核心成绩 (slides 3-8, 6 pages) ───

// 3. Core Result hero
(function(){
  const s=cSlide("核心成绩：PrimeVul 数据集上 F1 = 0.77");
  s.addText("0.77",{x:0.7,y:1.3,w:3.5,h:1.5,fontSize:72,color:C.accent,fontFace:"Arial",bold:true});
  s.addText("F1 Score",{x:0.7,y:2.7,w:3.5,h:0.4,fontSize:18,color:C.accent,fontFace:"Arial",bold:true});
  s.addText("精确率 + 召回率的调和平均\n0 = 最差，1 = 最好",{x:0.7,y:3.1,w:3.5,h:0.6,fontSize:11,color:C.muted,fontFace:"Arial",lineSpacingMultiple:1.2});
  // Test set explanation
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:4.5,y:1.3,w:4.8,h:3.0,fill:{color:C.cardBg},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.08});
  s.addText("测试集：PrimeVul",{x:4.7,y:1.4,w:4.4,h:0.35,fontSize:16,color:C.text,fontFace:"Arial",bold:true});
  bigBl(s,4.7,1.85,4.4,2.3,[
    "200 个代码片段，来自真实开源项目",
    "每个片段都标注了"+q("有没有漏洞"),
    "我们的任务：零样本判断每个片段是否有漏洞",
    "——不训练、不微调、不调参，直接测",
    "",
    "PrimeVul 是主测试集，另有 BigVul 交叉验证",
  ],C.accent);
})();

// 4. Four metrics
(function(){
  const s=cSlide("四个关键指标——每个都代表什么？");
  bigNum(s,0.5,1.4,2.1,1.3,"0.77","F1 Score\n精确率+召回率的调和平均\n综合衡量模型好坏",C.accent);
  bigNum(s,2.8,1.4,2.1,1.3,"0.78","Precision 精确率\n"+q("判有漏洞")+"的判断里\n多少真的有问题",C.success);
  bigNum(s,5.1,1.4,2.1,1.3,"0.75","Recall 召回率\n所有真实漏洞中\n我们找到了多少",C.warning);
  bigNum(s,7.4,1.4,2.1,1.3,"0.21","FPR 误报率\n安全代码被冤枉的概率\n(每100个安全代码≈21个)",C.danger);
  highlightBox(s,0.7,3.0,8.6,0.55,"通俗理解：Precision 高 = 不乱冤枉人 | Recall 高 = 不漏掉真漏洞 | F1 是两者的平衡");
  bigBl(s,0.7,3.75,8.6,1.3,[
    "ROC-AUC = 0.8356，PR-AUC = 0.7515 → 说明模型在不同判断阈值下都保持稳定表现，不是碰运气",
    "所有测试条件：零样本 · 纯代码输入 · 无微调 · 无代码属性图等额外信息",
  ],C.accent);
})();

// 5. What is Sink?
(function(){
  const s=cSlide(q("Sink")+" 是什么？——理解我们方案的关键概念");
  highlightBox(s,0.7,1.3,8.6,1.0,"Sink = 危险函数（Sink Function）——代码里调用了就可能产生安全漏洞的函数","FFF8E1");
  bigBl(s,0.7,2.55,8.6,1.2,[
    "strcpy(buf, src) → 字符串拷贝，如果 src 比 buf 长，就会溢出覆盖相邻内存",
    "memmove(ptr, data, n) → 内存移动，如果 n 没检查对，可能越界读写",
    "system(cmd) → 执行系统命令，如果 cmd 里拼了用户输入，就是命令注入漏洞",
  ],C.danger);
  s.addText("覆盖了 C/C++ 中 13 类常见漏洞的危险函数模式",{x:0.7,y:3.85,w:8.6,h:0.3,fontSize:12,color:C.muted,fontFace:"Arial"});
  highlightBox(s,0.7,4.3,8.6,0.55,"→ 代码里有这些函数的叫"+q("有 Sink")+"，没有的叫"+q("无 Sink")+" | PrimeVul 中：有 Sink 19 个（9.5%），无 Sink 181 个（90.5%）");
})();

// 6. PrimeVul breakdown
(function(){
  const s=cSlide("PrimeVul 分层结果：有 Sink vs 无 Sink");
  // Left: has sink
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.5,y:1.3,w:4.3,h:3.2,fill:{color:C.cardBg},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.08});
  s.addText("有 Sink 样本（19个，占 9.5%）",{x:0.7,y:1.4,w:3.9,h:0.35,fontSize:15,color:C.danger,fontFace:"Arial",bold:true});
  bigNum(s,1.2,1.85,2.0,1.0,"0.88","F1",C.danger);
  s.addText("P=0.90  R=0.85",{x:3.3,y:2.05,w:1.5,h:0.5,fontSize:11,color:C.text,fontFace:"Arial",bold:true});
  bigBl(s,0.7,3.05,3.9,1.2,[
    "代码里有危险函数 → 给了明确信号",
    ""+q("这里很可能有问题，请仔细看")+"",
    "这是表现最好的场景",
  ],C.danger);
  // Right: no sink
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:5.2,y:1.3,w:4.3,h:3.2,fill:{color:C.cardBg},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.08});
  s.addText("无 Sink 样本（181个，占 90.5%）",{x:5.4,y:1.4,w:3.9,h:0.35,fontSize:15,color:C.success,fontFace:"Arial",bold:true});
  bigNum(s,5.9,1.85,2.0,1.0,"0.74","F1",C.success);
  s.addText("P=0.76  R=0.73",{x:8.0,y:2.05,w:1.5,h:0.5,fontSize:11,color:C.text,fontFace:"Arial",bold:true});
  bigBl(s,5.4,3.05,3.9,1.2,[
    "没有危险函数提示 → 更难判断",
    "但占了 90.5%，是整体分数的绝对主力",
    "说明方案不是只在一两个简单样本上高分",
  ],C.success);
  highlightBox(s,0.7,4.7,8.6,0.5,"结论：绝大多数样本属于"+q("无Sink")+"的困难情况，我们的方案在这些困难样本上保持了 F1=0.74 的稳定表现");
})();

// 7. BigVul + Comparison
(function(){
  const s=cSlide("BigVul 数据集 + 学术横向对比");
  s.addText("BigVul Clean 数据集（200 样本）",{x:0.7,y:1.2,w:4,h:0.35,fontSize:15,color:C.text,fontFace:"Arial",bold:true});
  bigNum(s,0.7,1.6,2.0,1.0,"0.67","F1",C.accent);
  bigBl(s,3.0,1.65,6.3,1.0,[
    "Precision = 0.62，Recall = 0.74",
    "标签噪声率学术界估计约 75% → 如果 3/4 标签是错的，0.67 可能已接近数据集理论上限",
  ],C.accent);
  s.addText("学术对比：我们的 0.77 是什么水平？",{x:0.7,y:2.85,w:5,h:0.35,fontSize:15,color:C.text,fontFace:"Arial",bold:true});
  tbl(s,0.7,3.25,8.6,["方法","F1","条件","说明"],
    [["StarCoder2 7B","0.03","零样本","通用代码大模型 → 基本不可用"],
     ["CodeBERT","0.21","微调","专门拿漏洞数据训练过 → 仍然很低"],
     ["LLMxCPG","0.62-0.68","零样本+CPG","加了代码属性图 → 有改善但仍不如我们"],
     ["★ 我们的方案","0.77","零样本 纯代码 无微调","超过所有已知基线"]]);
})();

// 8. Results summary + Screenshot
(function(){
  const s=cSlide("全部测试结果汇总 + 系统展示");
  tbl(s,0.7,1.2,5.5,["数据集","样本数","F1","关键信息"],
    [["PrimeVul 全部","200","0.77","主测试集，分层测试"],
     ["└ 有 Sink 子集","19","0.88","危险函数明确 → 最高分"],
     ["└ 无 Sink 子集","181","0.74","占90.5%，真正驱动整体表现"],
     ["BigVul Clean","200","0.67","标签噪声~75%，可能接近上限"],
     ["Juliet 跨数据集","30","0.68","合成测试集，代码风格不同→泛化能力"]]);
  img(s,"屏幕截图 2026-07-21 135824.png",6.5,1.2,2.8,2.0);
  s.addText("我们搭建了完整可用的平台，不只是算法研究。",{x:0.7,y:3.55,w:8.6,h:0.3,fontSize:11,color:C.muted,fontFace:"Arial"});
  bigBl(s,0.7,3.9,8.6,1.1,[
    "Juliet 是合成测试集，代码风格和主测试集完全不同 → F1=0.68 证明方案有跨数据集泛化能力，不是只在一个数据集上过拟合",
  ],C.accent);
})();

// ─── Phase 1 (slides 9-22, 14 pages) ───

// 9. Section divider
secSlide("一","起点：Sink 注册表的过拟合\n与四个优化层的失效","从 0.9+ 的假象到踩坑——失败的尝试和成功的发现同等重要");

// 10. Core idea + 3 building blocks
(function(){
  const s=cSlide("初始想法很简单：让 AI 看代码，判断有没有漏洞");
  bigBl(s,0.7,1.3,8.6,0.6,["但要实现这个想法，需要三个东西——"],C.accent);
  const cards=[
    {t:"① Tree-sitter AST 解析",d:"代码在计算机眼里就是一串文本\nTree-sitter 把它变成一棵结构树\n每个节点 = 函数/变量/语句/表达式\n有了树，程序才能"+q("理解")+"代码\n\n支持 C/C++/Python/Java，免费开源",c:C.accent},
    {t:"② Sink 危险函数注册表",d:"预定义的列表，记录哪些函数危险\nstrcpy → 拷贝可能溢出\nsystem → 命令可能被注入\nmemmove → 参数没检查对可能越界\n\n共覆盖 13 类 C/C++ 漏洞",c:C.warning},
    {t:"③ Ollama 本地大模型",d:"在本机跑 AI，无需联网，数据不出本地\n一开始用 deepseek-r1 8B（80亿参数）\n后来支持多种模型接入：\n GLM-4.6V（智谱AI）\n DeepSeek V4 Flash\n Ollama 本地部署",c:C.success},
  ];
  cards.forEach(function(cc,i){card(s,0.3+i*3.2,2.2,3.0,2.8,cc.t,cc.d,cc.c);});
})();

// 11. LLM Config screenshot
scSlide("多种模型接入：LLM 配置界面","屏幕截图 2026-07-21 140338.png",
  "LLM 配置页面 — 后来从本地 deepseek-r1 8B 切换到了云端 GLM-4.6V（能力更强、推理更快）");

// 12. Data leak — the problem
(function(){
  const s=cSlide("坦诚交代：Sink 注册表的数据泄漏问题");
  highlightBox(s,0.7,1.2,8.6,0.8,"什么是数据泄漏？拿测试数据来指导规则设计，然后还在同一批数据上测试 → 就像考试前看了答案再去做题，分数高但没有任何意义","FFF8E1");
  bigBl(s,0.7,2.3,8.6,1.4,[
    "Sink 注册表是怎么来的？在一个早期的自建测试集上编写和调优——直接看测试样本里哪些函数出现频繁、哪些跟漏洞标注有关联，然后加进去",
    "这本质上相当于在那个小测试集上"+q("训练")+"了规则——犯了数据泄漏的错误",
  ],C.danger);
  bigBl(s,0.7,3.9,8.6,1.1,[
    "意识到问题后，我们立刻换了评测数据集——后续所有正式评测全部用 PrimeVul 和 BigVul",
    "这两个数据集跟我们写 sink 规则的自建集完全不重叠，sink 注册表也没有再根据新数据调整过",
  ],C.success);
})();

// 13. Data leak — impact assessment
(function(){
  const s=cSlide("数据泄漏的影响：方向性的而非持续性的");
  bigBl(s,0.7,1.3,8.6,2.0,[
    "为什么要客观评价？sink 函数本身就是通用的编程知识——strcpy 就是危险、system 就是可注入",
    "不管在哪个数据集上，这些函数的性质不变——这是语言层面的固有属性，不是数据集层面",
    "所以泄漏的影响是"+q("方向性的")+"而非"+q("持续性的")+"——注册表的框架思路来自早期数据，但具体条目的知识价值超越了数据集",
    "我们选择坦诚讲这个问题——学术诚信要求方法的局限性和犯错的地方都应该说清楚",
  ],C.accent);
  highlightBox(s,0.7,3.6,8.6,0.6,"关键是：后续所有正式评测用的数据集和早期自建集完全独立。写规则的测试集和评测成绩的测试集是不重叠的。");
})();

// 14. Four optimization layers
(function(){
  const s=cSlide("在基础框架上，我们又叠了四个"+q("优化层"));
  bigBl(s,0.7,1.2,8.6,0.6,["光有一个 sink 注册表太粗糙了，我们想让检测更准——但接下来会看到，这三层几乎全都没起作用。"],C.accent);
  const layers=[
    {t:"① 数据流追踪",d:"在函数内部从危险函数出发\n沿着变量赋值链路往回找外部输入\n\n用户输入→buf→strcpy = 一条数据流\nA函数→B函数→返回值→sink = 跨函数追踪",c:C.danger},
    {t:"② Sanitization 检测",d:"Sanitization = "+q("安全处理")+"\n用正则表达式去匹配：\n 边界检查、长度校验\n 参数化查询等防护措施\n\n覆盖 13 个漏洞类别，共 10 个正则",c:C.danger},
    {t:"③ 三阶段 LLM 推理",d:"让大模型分三步走：\n筛查 → 深度分析 → 自检\n\n每一步都调用一次模型\n使用 deepseek-r1 8B",c:C.danger},
    {t:"④ RAG 知识库",d:"RAG = 检索增强生成\n把已知漏洞案例存到向量数据库\n\n分析新代码时找最相似案例\n给 LLM 当参考",c:C.warning},
  ];
  layers.forEach(function(l,i){card(s,0.3+i*2.4,2.1,2.2,2.9,l.t,l.d,l.c);});
})();

// 15. Failure 1 — Data flow
(function(){
  const s=cSlide("失效 ①：数据流追踪——硬过滤器砍掉了真漏洞");
  highlightBox(s,0.7,1.15,8.6,0.5,"问题：把数据流追踪做成了"+q("硬过滤器")+"——没有数据流路径？直接判安全。一刀切。");
  bigBl(s,0.7,1.85,4.5,2.2,[
    "为什么这个逻辑是错的？",
    "函数参数天然就是外部输入的来源！",
    "调用方可能从用户输入、文件、网络读数据",
    "→ 函数参数天然就是一个 Source",
    "函数内部调用了 strcpy → 这就是 Sink",
    "从 Source 到 Sink，路径几乎总是存在",
    "→ 硬过滤条件没有区分度，等价于随机拦截",
  ],C.danger);
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:5.4,y:1.85,w:3.9,h:2.2,fill:{color:C.cardBg},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.06});
  s.addText("后果 + 修正",{x:5.6,y:1.95,w:3.5,h:0.3,fontSize:15,color:C.danger,fontFace:"Arial",bold:true});
  bigBl(s,5.6,2.35,3.5,1.5,[
    "砍掉了 17 个真漏洞",
    "不是拦住了误报",
    "是把真正的漏洞漏掉了",
    "",
    "修正：纯建议模式",
    "数据流信息仍然计算",
    "但只作参考不参与判决",
    "最终判断权还给 LLM",
  ],C.danger);
  highlightBox(s,0.7,4.35,8.6,0.55,"教训：静态分析的结果不应该做硬判决。区分度比覆盖面更重要。LLM 应该看到所有信号，自己做最终判断。");
})();

// 16. Failure 2a — Sanitization ideal vs real
(function(){
  const s=cSlide("失效 ②：Sanitization —— 理想代码 vs 真实代码（正则匹配不上）");
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.5,y:1.2,w:4.3,h:1.5,fill:{color:C.cardBg},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.06});
  s.addText("我们写正则时脑子里想的代码（理想化）",{x:0.7,y:1.3,w:3.9,h:0.3,fontSize:12,color:C.success,fontFace:"Arial",bold:true});
  s.addText("if (len > MAX) return;\nif (check_bound(buf, size))\n  handle(buf);",{x:0.7,y:1.7,w:3.9,h:0.8,fontSize:10,color:C.success,fontFace:"Courier New",lineSpacingMultiple:1.2});
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:5.2,y:1.2,w:4.3,h:1.5,fill:{color:C.cardBg},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.06});
  s.addText("实际遇到的真实项目代码",{x:5.4,y:1.3,w:3.9,h:0.3,fontSize:12,color:C.danger,fontFace:"Arial",bold:true});
  s.addText("#ifdef DEBUG\n  if (check_len(buf, sz))\n    handle_safe(buf);\n#endif",{x:5.4,y:1.7,w:3.9,h:0.8,fontSize:10,color:C.danger,fontFace:"Courier New",lineSpacingMultiple:1.2});
  bigBl(s,0.7,3.0,8.6,1.8,[
    "写了 10 个正则，6 个跟真实代码完全对不上——不是代码没有安全检查，是安全检查的写法千变万化，正则根本覆盖不了",
    "真实代码有：#ifdef 条件编译、宏包裹、嵌套函数调用——这些在写正则时根本没考虑到",
    "修正：sanitization 检测保留在 CodeSlicer 中，但只影响风险评级不做硬拦截",
    "正则匹配结果变成"+q("参考信号")+"给 LLM——"+q("这里可能做了防护，请你看看防护是否充分"),
  ],C.accent);
})();

// 17. Failure 2b — sizeof & strncpy gotchas
(function(){
  const s=cSlide("失效 ② 续：即使匹配到了"+"看起来像安全检查"+"的代码，也不代表真的安全");
  // sizeof
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.5,y:1.2,w:4.3,h:2.0,fill:{color:"FFF5F5"},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.06});
  s.addText("陷阱 1：sizeof(ptr) ≠ 安全",{x:0.7,y:1.3,w:3.9,h:0.35,fontSize:16,color:C.danger,fontFace:"Arial",bold:true});
  bigBl(s,0.7,1.75,3.9,1.3,[
    "很多程序员以为 sizeof 能防越界：",
    ""+q("先算缓冲区多大，只拷贝那么多")+"",
    "",
    "但 sizeof 对指针只返回指针本身大小",
    "x86-64 上永远是 8 个字节！",
    "如果你的数据是变长的",
    "——比如用户输入的一行文本",
    "sizeof 完全不保护你",
  ],C.danger);
  // strncpy
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:5.2,y:1.2,w:4.3,h:2.0,fill:{color:"FFF5F5"},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.06});
  s.addText("陷阱 2：strncpy ≠ 安全",{x:5.4,y:1.3,w:3.9,h:0.35,fontSize:16,color:C.danger,fontFace:"Arial",bold:true});
  bigBl(s,5.4,1.75,3.9,1.3,[
    "看起来比 strcpy 安全——限制拷贝长度",
    "但有一个著名的坑：",
    "",
    "如果源长度 ≥ 你限制的 n",
    "目标后面不会加结束符 \\0",
    "没有 \\0，后面读取的代码",
    "就会一直读下去",
    "读到非法内存——这也是漏洞",
  ],C.danger);
  highlightBox(s,0.7,3.5,8.6,0.55,"这就是为什么正则检测不够——看到了 sizeof/strncpy 不代表真的安全。需要 LLM 理解上下文做深度判断。");
})();

// 18. Failure 3 — 3-stage LLM
(function(){
  const s=cSlide("失效 ③：三阶段 LLM 推理——千分之十一的提升，几十倍的时间");
  s.addText("+0.011",{x:0.7,y:1.3,w:3.5,h:1.0,fontSize:56,color:C.danger,fontFace:"Arial",bold:true});
  s.addText("F1 提升（0.8657 → 0.8768）\n千分之十一 = 基本没变",{x:0.7,y:2.3,w:3.5,h:0.6,fontSize:12,color:C.muted,fontFace:"Arial",lineSpacingMultiple:1.2});
  bigBl(s,4.5,1.35,4.8,2.5,[
    "让 LLM 分三步：筛查 → 分析 → 自检",
    "每一步都调一次模型",
    "",
    "时间代价：单文件 40~120 秒",
    "是单次调用的很多倍",
    "",
    "为什么这么慢？",
    "① deepseek-r1 8B 对安全代码"+q("想太多"),
    "② 三步串行——筛查完等分析、分析完等自检",
    "③ 80亿参数本身对安全审计任务能力不够",
  ],C.danger);
  highlightBox(s,0.7,4.1,8.6,0.55,"根本原因：串行 Agent 链的延迟和错误会层层放大，而不是相互纠正。");
})();

// 19. Failure 3b — overfitting
(function(){
  const s=cSlide("59 样本 F1 > 0.9？——那是过拟合，假的");
  highlightBox(s,0.7,1.2,8.6,0.7,"59 个样本太少，没有统计区分度。任何一个稍微合理的方案都能刷到 0.9+。再加上 sink 注册表就是在这个小数据集上调的——高分更没说服力。");
  bigBl(s,0.7,2.2,8.6,1.5,[
    "后续换用 PrimeVul（200 样本），性能大幅下降——说明 0.9+ 是数据集太小 + 数据泄漏共同作用的结果",
    "这个阶段最大的价值不在于分数，而在于留下了一个非常重要的正确判断——",
  ],C.accent);
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.5,y:3.9,w:8.9,h:1.1,fill:{color:"E8F5E9"},rectRadius:0.06});
  s.addText("LLM 的正确角色是 "+q("发现")+" 而不是 "+q("验证"),{x:0.7,y:4.0,w:8.5,h:0.4,fontSize:22,color:C.success,fontFace:"Arial",bold:true});
  s.addText("应该去弥补静态工具的盲区，而不是重新发明静态工具已经做好的事",{x:0.7,y:4.45,w:8.5,h:0.4,fontSize:13,color:C.success,fontFace:"Arial"});
})();

// 20. LLM's role — blind spots
(function(){
  const s=cSlide("LLM 应该弥补什么样的盲区？——静态工具完全看不到的漏洞");
  const bs=[
    {t:"逻辑漏洞",d:"代码逻辑本身有 bug\n但不是某个具体的危险函数导致的\n\n比如：条件判断写反了\n变量覆盖了、分支永远进不去",c:C.accent},
    {t:"UAF\n释放后再使用",d:"Use After Free\n\nmalloc 在 A 函数分配\nfree 在 B 函数释放\nC 函数还在用那个指针\n\n不涉及任何 sink 函数",c:C.danger},
    {t:"竞态条件",d:"Race Condition\n\n多线程同时访问同一个数据\n执行顺序不确定导致出bug\n\n没有危险函数，没有固定模式\n静态工具完全检测不到",c:C.warning},
    {t:"LLM 不该做什么",d:"sink 函数检测\n缓冲区溢出判断\n危险函数模式匹配\n\n这些用规则就能搞定\n不需要浪费 LLM 的算力\n\nLLM 应该去规则够不着的地方",c:C.success},
  ];
  bs.forEach(function(b,i){card(s,0.3+i*2.4,1.35,2.2,3.5,b.t,b.d,b.c);});
})();

// 21. Four lessons
(function(){
  const s=pres.addSlide();s.background={fill:C.primary};
  s.addText("Phase 1 教会我们四件事",{x:0.7,y:0.6,w:5,h:0.55,fontSize:16,color:C.accent,fontFace:"Arial",bold:true});
  const lessons=[
    {t:"不要堆砌优化层",d:"四个层叠上去\n三个没起作用\n一个起了反作用\n\n每加一个东西\n都要验证它真的有贡献",c:C.danger},
    {t:"不要在测试集\n上写规则",d:"这就是数据泄漏\n刷出来的高分\n没有任何意义\n\n哪怕是无心之举\n也必须警惕",c:C.warning},
    {t:"不要用静态分析\n做硬判决",d:"静态分析的结论\n应该当成信号、参考\n\n最终判断权\n必须在 LLM 手里\n不能把人拦在门外",c:C.danger},
    {t:"LLM 的目标\n是补偿盲区",d:"去做静态工具\n做不了的事\n\n逻辑漏洞/UAF/竞态\n这些才是 LLM 的\n真正价值所在",c:C.success},
  ];
  lessons.forEach(function(l,i){
    const x=0.4+i*2.4;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:x,y:1.5,w:2.2,h:3.3,fill:{color:"192D45"},rectRadius:0.08});
    s.addShape(pres.shapes.RECTANGLE,{x:x,y:1.5,w:2.2,h:0.05,fill:{color:l.c}});
    s.addText(l.t,{x:x+0.12,y:1.65,w:1.95,h:1.2,fontSize:14,color:l.c,fontFace:"Arial",bold:true,lineSpacingMultiple:1.2});
    s.addText(l.d,{x:x+0.12,y:3.0,w:1.95,h:1.6,fontSize:10,color:C.muted,fontFace:"Arial",lineSpacingMultiple:1.3});
  });
  s.addText("这四个教训直接决定了我们后面的架构设计",{x:0.7,y:4.95,w:8.6,h:0.3,fontSize:11,color:C.muted,fontFace:"Arial",align:"center"});
})();

// 22. Transition — handing off
(function(){
  const s=cSlide("小结 + 接下来");
  bigBl(s,0.7,1.3,8.6,2.5,[
    "我们从一个朴素的起点出发——让 AI 看代码判断漏洞",
    "搭建了 Tree-sitter + Sink 注册表 + LLM 的基础框架",
    "叠了四层优化，发现三层失效——交了不少学费",
    "但学到了最关键的教训：LLM 该做什么、不该做什么",
    "这些经验直接决定了后面 Phase 2 和 Phase 3 的架构方向",
    "",
    "接下来由我的组员介绍：",
    "Phase 2：模块化拆解 + LLM 层层杀 TP + 静态拦截问题的发现",
    "Phase 3：V4 工具感知链架构——三工具 + 三 Agent + 后处理的完整方案",
  ],C.accent);
})();

// ════════════════════════════════════════════
// SECTION B: Phase 2, Phase 3, 消融, 局限性, 总结
// (slides 23-48)
// ════════════════════════════════════════════

// 23. Section: Phase 2
secSlide("二","模块化：发现 LLM 层层杀 TP\n与静态拦截问题","从 Ollama R1 切换到云端 GLM-4.6V，管道拆解为可配置模块");

// 24. Architecture + 4 modes
(function(){
  const s=cSlide("模块化架构拆分 + 四种 LLM 策略模式");
  s.addText("管道四层可配置架构",{x:0.7,y:1.1,w:4,h:0.3,fontSize:13,color:C.text,fontFace:"Arial",bold:true});
  const layers=["静态决策层\n(可配拦截策略)","代码窗口层\n(可配截取长度)","LLM 策略层\n(可配推理模式)","后处理层\n(可配校准规则)"];
  layers.forEach(function(l,i){
    s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.7+i*2.2,y:1.45,w:1.9,h:0.7,fill:{color:C.cardBg},rectRadius:0.06});
    s.addText(l,{x:0.7+i*2.2,y:1.47,w:1.9,h:0.65,fontSize:9,color:C.accent,fontFace:"Arial",bold:true,align:"center",lineSpacingMultiple:1.2});
  });
  s.addText("四种 LLM 策略模式（同一管道可切换）",{x:0.7,y:2.35,w:5,h:0.3,fontSize:13,color:C.text,fontFace:"Arial",bold:true});
  const modes=[
    {t:"模式一：单次推理",d:"一次 LLM 调用，直接输出结构化判断结果\ntoken 消耗最低，适合快速扫描场景\n效果取决于代码窗口质量和 prompt 清晰度",c:C.accent},
    {t:"模式二：三级 Agent 链",d:"Agent1 CWE 专项筛查（思维链逐步推理）\nAgent2 复审查验（可配保守/激进策略）\nAgent3 盲区扫描（检查未覆盖代码区域）",c:C.secondary},
    {t:"模式三：多温度投票",d:"Agent1 筛查后 Agent2 在三温度推理\n0.0（保守）/ 0.3（均衡）/ 0.7（发散）\n置信度加权投票，利用多样性降误判",c:C.warning},
    {t:"模式四：工具感知链 ★",d:"静态分析工具报告 → Agent 差异分析\n这是我们最终采用的方案，后面详细展开\n融合三个工具信号指导 LLM 推理",c:C.success},
  ];
  modes.forEach(function(m,i){card(s,0.4+i*2.4,2.7,2.2,2.55,m.t,m.d,m.c);});
})();

// 25. LLM kills TP
(function(){
  const s=cSlide("核心矛盾：LLM Agent 层层杀 TP，不增 TP");
  s.addText("24 TP",{x:0.7,y:1.3,w:1.5,h:0.5,fontSize:30,color:C.success,fontFace:"Arial",bold:true,align:"center"});
  s.addText("静态工具找到",{x:0.7,y:1.8,w:1.5,h:0.25,fontSize:8,color:C.muted,fontFace:"Arial",align:"center"});
  s.addText("→",{x:2.3,y:1.35,w:0.3,h:0.4,fontSize:20,color:C.muted,fontFace:"Arial"});
  s.addText("Agent1 CoT\n-5~6 TP",{x:2.7,y:1.25,w:1.5,h:0.7,fontSize:11,color:C.danger,fontFace:"Arial",bold:true,align:"center"});
  s.addText("→",{x:4.3,y:1.35,w:0.3,h:0.4,fontSize:20,color:C.muted,fontFace:"Arial"});
  s.addText("Agent2 复审\n-3~8 TP",{x:4.7,y:1.25,w:1.5,h:0.7,fontSize:11,color:C.danger,fontFace:"Arial",bold:true,align:"center"});
  s.addText("→",{x:6.3,y:1.35,w:0.3,h:0.4,fontSize:20,color:C.muted,fontFace:"Arial"});
  s.addText("10-19 TP",{x:6.7,y:1.3,w:1.5,h:0.5,fontSize:30,color:C.danger,fontFace:"Arial",bold:true,align:"center"});
  s.addText("最终幸存",{x:6.7,y:1.8,w:1.5,h:0.25,fontSize:8,color:C.muted,fontFace:"Arial",align:"center"});
  bigBl(s,0.7,2.4,8.6,2.8,[
    "BigVul 52 样本实验揭示：LLM Agent 的每一步审查都在削减 TP（真阳性），而非发现新的 TP——每多一层 Agent，就多一道杀 TP 的风险",
    "最终 10~19 个 TP 是从初始 24 个中"+q("幸存")+"下来的，而非新增——LLM 的全部价值都体现在削减误报上",
    "核心启示：Agent 链不能设计为"+q("层层审批")+"——Agent 的角色应该是互补而非串行审批",
  ],C.danger);
})();

// 26. Code window
(function(){
  const s=cSlide("反直觉发现：代码窗口不是越大越好");
  bigNum(s,0.7,1.4,2.5,1.2,"F1=0.60","截取前 1500 字符",C.success);
  s.addText(">",{x:3.3,y:1.6,w:0.5,h:0.6,fontSize:28,color:C.muted,fontFace:"Arial",bold:true});
  bigNum(s,3.8,1.4,2.5,1.2,"F1=0.42","截取前 3000 字符",C.danger);
  bigBl(s,0.7,2.9,8.6,2.2,[
    "函数签名 + 变量声明 = 最关键上下文 → 告诉 LLM 变量类型、大小、来源",
    "1500 字符刚好覆盖这些关键信息 → 信噪比最优",
    "3000 字符灌入后面不相关的代码 → 噪声干扰判断，F1 反而下降",
    "启示：上下文不是越大越好——噪声成本可能超过信息收益。这直接催生了 V4 的动态窗口策略",
  ],C.accent);
})();

// 27. Screenshot: Scanner
scSlide("代码扫描界面：单样本分析与结果展示","屏幕截图 2026-07-21 140210.png",
  "代码扫描页面 — 左侧代码输入区，右侧 LLM 分析结果（漏洞类型、风险等级、推理过程）");

// 28. Static blocking
(function(){
  const s=cSlide("静态决策层在杀死性能——架构把主角拦在门外");
  tbl(s,0.7,1.3,8.6,["配置","关键参数","F1","LLM调用","说明"],
    [["V2 预设","no_sink=safe","0.00","0","30样本全部被拦截，LLM一次都没运行"],
     ["V3 预设","三把锁同时锁死","0.00","0","no_sink=safe, low_risk_sink=safe, sanitizer_threshold=2"],
     ["关闭拦截","单次LLM+完整代码","0.67","28","F1从0跳到0.67——翻了无穷倍"]]);
  bigBl(s,0.7,3.0,8.6,2.2,[
    "关掉所有拦截后 F1 从 0.00 跳到 0.67：之前 V1-V3 低分不是因为 LLM 能力不足，而是静态层没让它上场！",
    "这直接决定了 V4 的核心设计原则：静态分析只提供信号，不做硬判决。所有样本都必须经过 LLM 推理",
  ],C.accent);
})();

// 29. Phase 2 summary
(function(){
  const s=pres.addSlide();s.background={fill:C.primary};
  s.addText("Phase 2 关键发现",{x:0.7,y:0.7,w:4,h:0.5,fontSize:14,color:C.accent,fontFace:"Arial",bold:true});
  s.addText("不要用静态分析代替 LLM 判断。\nLLM 管道中每一层都在杀 TP，\nAgent 的角色应该是互补而非串行审批。",{x:0.7,y:1.6,w:8.6,h:2.0,fontSize:22,color:C.white,fontFace:"Cambria",bold:true,lineSpacingMultiple:1.3});
  const pills=[{t:"LLM 只削减误报不发现新漏洞",c:C.warning},{t:"代码窗口不是越大越好",c:C.accent},{t:"静态拦截是最大的人为损害",c:C.danger},{t:"LLM 必须看到所有样本",c:C.success}];
  pills.forEach(function(p,i){s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.7+i*2.3,y:4.0,w:2.0,h:0.7,fill:{color:"1A2D45"},rectRadius:0.15});s.addText(p.t,{x:0.8+i*2.3,y:4.05,w:1.8,h:0.6,fontSize:9,color:p.c,fontFace:"Arial",bold:true,align:"center",lineSpacingMultiple:1.2});});
})();

// 30. Section: Phase 3
secSlide("三","V4：三级 Agent\n+ 工具感知链","架构重建：工具聚合 → LLM 推理 → 后处理。静态工具提供信号，LLM 做全部判决");

// 31. V4 Pipeline
(function(){
  const s=cSlide("V4 工具感知链：整体管道架构（七个阶段）");
  const stages=[
    {t:"工具聚合",sub:"CodeSlicer\nCodeQL\nSemgrep\n并行运行",c:C.accent},
    {t:"共识分析",sub:"2+工具=高信号\n单工具=中信号\n全沉默=无信号",c:C.secondary},
    {t:"Agent1\n差异分析",sub:"只看报告\n不看代码\n三输出决策",c:C.accent},
    {t:"有 Sink\nAgent2 激进验证",sub:"假设可达\n有罪推定\nplausible=漏洞",c:C.danger},
    {t:"无 Sink\nAgent2 Checklist",sub:"六类审计\n逐项填表\n消除猜测",c:C.success},
    {t:"Agent3\n盲区扫描",sub:"只找漏洞\n不判安全\n独立运行",c:C.warning},
    {t:"后处理",sub:"冲突仲裁\n置信度校准\n质量检查",c:C.muted},
  ];
  stages.forEach(function(st,i){
    const x=0.25+i*1.38;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:x,y:1.3,w:1.28,h:2.2,fill:{color:C.cardBg},shadow:{type:"outer",blur:2,offset:1,color:"000000",opacity:0.05},rectRadius:0.06});
    s.addShape(pres.shapes.RECTANGLE,{x:x+0.04,y:1.35,w:0.04,h:2.1,fill:{color:st.c}});
    s.addText(st.t,{x:x+0.14,y:1.35,w:1.1,h:0.75,fontSize:9,color:C.text,fontFace:"Arial",bold:true,lineSpacingMultiple:1.15});
    s.addText(st.sub,{x:x+0.14,y:2.1,w:1.1,h:1.2,fontSize:7.5,color:C.muted,fontFace:"Arial",lineSpacingMultiple:1.15});
    if(i<stages.length-1)s.addText("▸",{x:x+1.24,y:2.0,w:0.2,h:0.4,fontSize:12,color:C.muted,fontFace:"Arial",align:"center"});
  });
  s.addText("核心设计原则：静态分析只提供信号，不做硬判决。所有样本都必须经过 LLM 推理。",{x:0.7,y:3.8,w:8.6,h:0.3,fontSize:10,color:C.muted,fontFace:"Arial",align:"center"});
})();

// 32. Tool aggregation (abbreviated - keep original content)
(function(){
  const s=cSlide("工具聚合层：三个静态分析引擎");
  tbl(s,0.7,1.2,8.6,["工具","类型","核心优势","主要盲区","典型检出漏洞"],
    [["CodeSlicer（自研）","tree-sitter AST","零外部依赖/毫秒级/精确定位到行","无跨函数分析/无指针别名","sink函数调用/危险模式"],
     ["CodeQL（GitHub）","CFG+DFG污点追踪","跨函数漏洞检测/企业级引擎","需合法语法/截断代码兼容差","UAF/整数溢出/跨函数漏洞"],
     ["Semgrep","AST模式匹配","极快/YAML规则可定制/社区生态","浅层语法匹配/无语义推理","已知漏洞模式/代码规范"]]);
  s.addText("注：还集成了 Flawfinder 和 Cppcheck | 共识分析：≥2工具共识=高信号 | 单工具=中信号 | 全沉默=无信号（需盲区扫描）",{x:0.7,y:2.9,w:8.6,h:0.25,fontSize:9,color:C.muted,fontFace:"Arial"});
  bigBl(s,0.7,3.3,8.6,1.8,[
    "三个工具输出经格式归一化 → 共识分析 + 盲区识别 → 结构化报告（通常只有几百 token，远小于完整代码）",
    "最终产出的结构化工具报告直接喂给 Agent1——这是模式四与其他三种模式的本质区别",
  ],C.accent);
})();

// 33. Agent1
(function(){
  const s=cSlide("Agent1：只看工具报告，不看原始代码");
  const reasons=[
    {t:"原因一：保持交叉验证意义",d:"如果 Agent1 先看代码就会形成自己的预判，失去多工具交叉验证的价值。Agent1 的角色是"+q("差异分析师")+"——识别工具之间的共识和分歧，不是初级审计员。",c:C.accent},
    {t:"原因二：极大节约上下文窗口",d:"工具报告通常只有几百个 token，而完整代码可能有几千甚至上万 token。把宝贵的 token 预算留给 Agent2 和 Agent3 的深度代码分析。",c:C.success},
  ];
  reasons.forEach(function(r,i){card(s,0.7+i*4.5,1.3,4.2,1.3,r.t,r.d,r.c);});
  s.addText("Agent1 输出三个关键决策（不是最终判决）",{x:0.7,y:2.85,w:5,h:0.3,fontSize:13,color:C.text,fontFace:"Arial",bold:true});
  tbl(s,0.7,3.2,8.6,["决策字段","含义","可选值","对下游的影响"],
    [["initial_verdict","是否值得继续审查","suspicious / not suspicious","决定是否触发 Agent2 深度分析"],
     ["window_suggestion","建议的代码窗口大小","iris (±5行) / medium / full","决定传给 Agent2 的代码截取范围"],
     ["blind_spot_risk","工具组合可能遗漏的风险","UAF / 竞态 / 逻辑缺陷 等","补充到 Agent2 的 checklist 审计项"]]);
})();

// 34. Sink vs No-Sink
(function(){
  const s=cSlide("核心设计分歧：有 Sink 和无 Sink，两条路径");
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.4,y:1.25,w:4.4,h:3.7,fill:{color:C.cardBg},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.08});
  s.addText("● 有 Sink → confirm_it 激进验证",{x:0.6,y:1.35,w:4.0,h:0.35,fontSize:14,color:C.danger,fontFace:"Arial",bold:true});
  bigBl(s,0.6,1.8,4.0,2.9,[
    "原则1：假设 sink 始终可达，除非有硬证据证明不可达",
    "原则2：对清理措施做有罪推定——sizeof 对变长数据不保护，strncpy 不保证空终止",
    "原则3：只有证明漏洞不可能时才判 safe——存在一种 plausible 的利用路径就判漏洞",
    "为什么激进？安全审计场景下漏报代价远大于误报",
    "对比实验：保守策略（Agent2 做驳回员）→ 大量真漏洞被漏掉",
    "激进策略→召回率显著提升，代价是精确率有一定下降（这个取舍值得）",
  ],C.danger);
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:5.2,y:1.25,w:4.4,h:3.7,fill:{color:C.cardBg},shadow:{type:"outer",blur:3,offset:1,color:"000000",opacity:0.05},rectRadius:0.08});
  s.addText("○ 无 Sink → checklist 六类审计",{x:5.4,y:1.35,w:4.0,h:0.35,fontSize:14,color:C.success,fontFace:"Arial",bold:true});
  bigBl(s,5.4,1.8,4.0,2.9,[
    "所有工具沉默 ≠ 代码安全——UAF/竞态/off-by-one 不对应任何 sink 模式",
    "让 LLM 逐项填表：MEMORY项→UAF=YES/NO 证据行X；INTEGER项→溢出=YES/NO 证据行Y",
    "从模糊的"+q("可能有漏洞")+"变成具体的是/否+行号——大幅减少猜测空间",
    "消融验证：通用扫描 F1=0.62 → Checklist F1=0.74（+19%）",
  ],C.success);
})();

// 35. Checklist 6 categories
(function(){
  const s=cSlide("Checklist 六类专项审计：基于 CWE Top 25 + OWASP");
  const cats=[
    {t:"① 内存安全 MEMORY",items:"UAF / 双重释放\n内存泄漏 / 悬垂指针",c:C.danger},
    {t:"② 整数安全 INTEGER",items:"溢出/下溢/截断\n有符号/无符号转换错误",c:C.warning},
    {t:"③ 边界安全 BOUNDARY",items:"数组越界读写\nOff-by-one 错误",c:C.warning},
    {t:"④ 并发安全 CONCURRENCY",items:"竞态条件/TOCTOU\n死锁/活锁",c:C.accent},
    {t:"⑤ 错误路径 ERROR PATHS",items:"空指针解引用\n资源泄漏/返回值忽略",c:C.accent},
    {t:"⑥ 逻辑缺陷 LOGIC",items:"条件恒真/恒假\n分支缺失/索引越界",c:C.success},
  ];
  cats.forEach(function(cat,i){
    const col=i%3,row=Math.floor(i/3),x=0.45+col*3.1,y=1.25+row*1.7;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x,y,w:2.9,h:1.45,fill:{color:C.cardBg},shadow:{type:"outer",blur:2,offset:1,color:"000000",opacity:0.04},rectRadius:0.06});
    s.addShape(pres.shapes.RECTANGLE,{x,y,w:2.9,h:0.045,fill:{color:cat.c}});
    s.addText(cat.t,{x:x+0.1,y:y+0.1,w:2.7,h:0.3,fontSize:11,color:cat.c,fontFace:"Arial",bold:true});
    s.addText(cat.items,{x:x+0.1,y:y+0.45,w:2.7,h:0.85,fontSize:9,color:C.text,fontFace:"Arial",lineSpacingMultiple:1.25});
  });
  s.addText("消融验证：通用全面扫描 F1=0.62 → Checklist 逐项填表 F1=0.74（+19%）",{x:0.7,y:4.85,w:8.6,h:0.25,fontSize:11,color:C.accent,fontFace:"Arial",bold:true});
})();

// 36. Screenshot: Pipeline
scSlide("V4 工具感知链：详细推理过程展示","屏幕截图 2026-07-21 140713.png",
  "Agent 链详细输出 — 每个 Agent 的中间推理过程、工具信号、最终判决");

// 37. Agent3
(function(){
  const s=cSlide("Agent3：盲区扫描器——只找漏洞，不判安全");
  s.addText("Agent3 工作机制",{x:0.7,y:1.2,w:4.2,h:0.35,fontSize:14,color:C.text,fontFace:"Arial",bold:true});
  bigBl(s,0.7,1.55,4.2,3.2,[
    "触发条件：仅当 Agent2 判 safe 或 uncertain 时触发——Agent2 已确认漏洞的样本不需要再跑",
    "触发率：短函数 0% → 长函数约 20%，200 样本总计触发十几次，集中在 >3000 字符长函数",
    "核心原则：只找漏洞，不判安全——发现了就补进结果，没发现也不代表代码安全",
    "独立运行，不受 Agent2 结论影响——prompt 和 checklist 审计一样，但判断独立",
  ],C.accent);
  s.addText("意外发现",{x:5.1,y:1.2,w:4.2,h:0.35,fontSize:14,color:C.text,fontFace:"Arial",bold:true});
  bigBl(s,5.1,1.55,4.2,3.2,[
    "⚡ A3 + 仲裁实际上在架空 Agent2",
    "Agent2 判安全 → Agent3 重新扫描",
    "→ A3 通常能找到 Agent2 遗漏的漏洞",
    "→ 冲突仲裁器随后推翻 A2 的结论",
    "意味着 Agent2 的倾向性被 A3 完全覆盖",
    "最终判决由 A3 主导而非 A2",
    "后期 Agent 可能"+q("覆盖")+"而非"+q("协作")+"前期 Agent",
  ],C.warning);
})();

// 38. Post-processing
(function(){
  const s=cSlide("后处理层：三个零 LLM 成本的校准模块");
  const mods=[
    {t:"冲突仲裁器",d:"A2 与 A3 结论不一致时触发。三条规则：① A3 在 A2 焦点窗口外发现具体问题 → A3 胜出（A2 没看到那段代码）；② A3 推理模糊、A2 推理具体 → A2 胜出（模糊信号不能推翻明确判断）；③ 各有道理但针对不同区域 → 可同时成立，最终判漏洞。",c:C.danger},
    {t:"置信度校准器",d:"纯规则引擎，不调 LLM。A2 和 A3 结论一致 → +0.05~0.10；A3 独立发现盲区漏洞且证据充分 → +0.05~0.10；reasoning 文本出现模糊措辞（"+q("可能")+"/"+q("或许")+"）→ -0.05~0.10；多工具共识 → +0.03。调节量都不大，主要防止单个过度自信的判断主导输出。",c:C.accent},
    {t:"输出质量检查器",d:"最简单的模块，捕获三种异常：① 判了 vuln 但推理文本为空 → 把置信度压到很低（无理由判断不可靠）；② 置信度极高但推理文本极短 → 纠正到合理值（过度自信=推理不充分）；③ 方法标注为 LLM 但置信度异常低 → 提到最低门槛（避免 LLM 在不该犹豫时犹豫）。",c:C.success},
  ];
  mods.forEach(function(m,i){const y=1.2+i*1.3;s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.7,y,w:8.6,h:1.15,fill:{color:C.cardBg},rectRadius:0.06});s.addShape(pres.shapes.RECTANGLE,{x:0.7,y,w:0.05,h:1.15,fill:{color:m.c}});s.addText(m.t,{x:0.9,y:y+0.05,w:3,h:0.25,fontSize:12,color:m.c,fontFace:"Arial",bold:true});s.addText(m.d,{x:0.9,y:y+0.32,w:8.2,h:0.75,fontSize:9,color:C.text,fontFace:"Arial",lineSpacingMultiple:1.2});});
})();

// 39. Section: Ablation
secSlide("四","消融实验：控制变量法\n拆解每个组件的贡献","30 样本分层抽样 × 5 种配置 × 5 项关键结论");

// 40. Ablation table
(function(){
  const s=cSlide("消融实验结果：每次只改一个变量，其余与 V4 一致");
  tbl(s,0.7,1.3,8.6,["配置","F1","Precision","Recall","LLM调用","说明"],
    [["基线：单次 LLM 调用","0.40","0.67","0.29","28","完整代码+清晰prompt，已是不错的基线"],
     ["V4 三层 Agent（完整）","0.62","0.67","0.57","67","+55% F1, ~3× token"],
     ["V4 关闭 RAG","0.62","0.67","0.57","67","F1 完全不变 → RAG 零贡献"],
     ["V4 多温度投票","0.62","0.67","0.57","89","调用+33%，F1 无任何提升"],
     ["单次调用 + 静态拦截","0.13","1.00","0.07","1","28 样本仅 1 次 LLM → 灾难"]]);
  bigBl(s,0.7,3.5,8.6,1.7,[
    "三层 Agent 将 F1 从 0.40 提升到 0.62（+55%），200 样本上从约 0.67 提升到 0.77（+15%）",
    "提升来源：checklist 结构化审计 + 工具信号引导。代价：约 3 倍 token 消耗",
    "静态拦截是最大损害——F1 从 0.40 暴跌到 0.13，Precision 虽 1.00 但 Recall 仅 0.07",
  ],C.accent);
})();

// 41. Screenshot: Evaluation
scSlide("批量评测界面：数据集选择与评测结果","屏幕截图 2026-07-21 140304.png",
  "批量评测页面 — 数据集选择、预设配置、评测进度与 F1/Precision/Recall 结果展示");

// 42. Ablation findings 1&2
(function(){
  const s=cSlide("消融结论 ①②：RAG 零贡献 + 静态拦截是最大损害");
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.7,y:1.2,w:8.6,h:1.7,fill:{color:C.cardBg},rectRadius:0.06});
  s.addShape(pres.shapes.RECTANGLE,{x:0.7,y:1.2,w:0.05,h:1.7,fill:{color:C.danger}});
  s.addText("① RAG 零贡献——完整管线搭建完毕但毫无作用",{x:0.9,y:1.25,w:8.2,h:0.3,fontSize:14,color:C.danger,fontFace:"Arial",bold:true});
  bigBl(s,0.9,1.6,8.2,1.15,[
    "完整管线：SiliconFlow bge-m3 嵌入(1024维) → ChromaDB(NVD 25万+CISA KEV 1647=5.9万文档)",
    "关闭 RAG 后 F1 完全不变；根因：CVE 元数据描述漏洞影响不含代码模式，bge-m3 通用文本嵌入匹配失败",
  ],C.danger);
  s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.7,y:3.1,w:8.6,h:1.7,fill:{color:C.cardBg},rectRadius:0.06});
  s.addShape(pres.shapes.RECTANGLE,{x:0.7,y:3.1,w:0.05,h:1.7,fill:{color:C.danger}});
  s.addText("② 静态拦截——不是性能差，是架构把主角拦在门外",{x:0.9,y:3.15,w:8.2,h:0.3,fontSize:14,color:C.danger,fontFace:"Arial",bold:true});
  bigBl(s,0.9,3.5,8.2,1.15,[
    "no_sink=safe → F1 从 0.40 降到 0.13，28 样本仅 1 次 LLM 调用，96% 样本被拦截",
    "启示：在 LLM-based 管道中，任何硬拦截都是危险的。静态工具应提供信号而非判决",
  ],C.danger);
})();

// 43. Ablation findings 3-5
(function(){
  const s=cSlide("消融结论 ③④⑤：多温度无效 + 单次强基线 + A3 架空 A2");
  const findings=[
    {num:"③",t:"多温度投票换不来提升",d:"三温度(0.0/0.3/0.7)加权投票 F1 持平但调用+33%。结论：DeepSeek V4 Flash 温度变化不足以产生有效推理多样性。保留为可配置选项但不推荐。",c:C.warning},
    {num:"④",t:"单次 LLM 调用就是强基线",d:"完整代码+清晰 prompt → F1=0.40，超过所有带静态拦截的配置（V2/V3 的 0.00）。三层 Agent 提升 55% → 0.62。提升来自 checklist 结构化审计和工具信号引导，代价约 3× token。",c:C.accent},
    {num:"⑤",t:"A3 + 仲裁在架空 Agent2",d:"Agent2 判安全 → A3 找到遗漏漏洞 → 仲裁推翻 A2。Agent2 的倾向性被 A3 完全覆盖，最终判决由 A3 主导。多层 Agent 未必互补，可能只是后者覆盖前者。",c:C.warning},
  ];
  findings.forEach(function(f,i){const y=1.2+i*1.3;s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.7,y,w:8.6,h:1.15,fill:{color:C.cardBg},rectRadius:0.06});s.addShape(pres.shapes.RECTANGLE,{x:0.7,y,w:0.05,h:1.15,fill:{color:f.c}});s.addText(f.num+" "+f.t,{x:0.9,y:y+0.05,w:8.2,h:0.25,fontSize:12,color:f.c,fontFace:"Arial",bold:true});s.addText(f.d,{x:0.9,y:y+0.33,w:8.2,h:0.72,fontSize:9,color:C.text,fontFace:"Arial",lineSpacingMultiple:1.2});});
})();

// 44. Section: Limitations
secSlide("五","局限性与坦诚讨论","哪些地方做得不够好，以及为什么。学术诚信：必须说清楚方案的边界");

// 45. Limitations 1-3
(function(){
  const s=cSlide("方案局限性 ①②③");
  const limits=[
    {t:"① RAG 模块无实际贡献",d:"完整基础设施但未产生价值。bge-m3 通用文本嵌入在代码和漏洞描述间匹配失败。方向正确但嵌入方案选型不对——未来用 CodeBERT/UniXcoder 可能释放 RAG 价值。",c:C.danger},
    {t:"② 数据流追踪仅限单函数",d:"只在函数作用域内做追踪，不做跨过程分析。真实漏洞涉及多函数交互——malloc(A)→free(B)→UAF(C)。单函数分析完全看不到这种模式。",c:C.warning},
    {t:"③ 上下文长度要求高，Token 消耗大",d:"长函数 token 消耗大，动态窗口能部分缓解不能根本解决。三层架构约 3 倍 token 消耗，生产环境中需权衡成本效益。",c:C.warning},
  ];
  limits.forEach(function(l,i){const y=1.2+i*1.3;s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.7,y,w:8.6,h:1.15,fill:{color:C.cardBg},rectRadius:0.06});s.addShape(pres.shapes.RECTANGLE,{x:0.7,y,w:0.05,h:1.15,fill:{color:l.c}});s.addText(l.t,{x:0.9,y:y+0.05,w:8.2,h:0.25,fontSize:12,color:l.c,fontFace:"Arial",bold:true});s.addText(l.d,{x:0.9,y:y+0.33,w:8.2,h:0.75,fontSize:9,color:C.text,fontFace:"Arial",lineSpacingMultiple:1.2});});
})();

// 46. Limitations 4-6
(function(){
  const s=cSlide("方案局限性 ④⑤⑥");
  const limits=[
    {t:"④ 测试集标签噪声严重——可能已达数据集理论上限",d:"PrimeVul 93% 样本 CWE 为空，Chrome 代码重构 commit 被标为漏洞。BigVul 噪声率约 75%。如果 3/4 标签是错的，F1=0.67 可能已接近上限。改进标签质量是未来重要方向。",c:C.danger},
    {t:"⑤ 仅在函数级代码片段上测试——缺少真实项目级验证",d:"只测了 C/C++/Python 函数级片段。缺少项目级构建上下文、类型信息和跨文件调用。真实安全审计需要完整调用链。",c:C.warning},
    {t:"⑥ 数据集分布决定组件贡献——评测数字不能脱离数据分布",d:"PrimeVul 90.5% 无 sink → checklist 是真正驱动力。换到有 sink 主导的数据集，激进验证策略会有更大空间。任何评测都是方法和数据集交互的结果。",c:C.accent},
  ];
  limits.forEach(function(l,i){const y=1.2+i*1.3;s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.7,y,w:8.6,h:1.15,fill:{color:C.cardBg},rectRadius:0.06});s.addShape(pres.shapes.RECTANGLE,{x:0.7,y,w:0.05,h:1.15,fill:{color:l.c}});s.addText(l.t,{x:0.9,y:y+0.05,w:8.2,h:0.25,fontSize:12,color:l.c,fontFace:"Arial",bold:true});s.addText(l.d,{x:0.9,y:y+0.33,w:8.2,h:0.75,fontSize:9,color:C.text,fontFace:"Arial",lineSpacingMultiple:1.2});});
})();

// 47. Project journey
(function(){
  const s=cSlide("项目迭代历程：四个版本的关键转变");
  tbl(s,0.7,1.3,8.6,["版本","核心架构","关键问题","F1(BigVul30)","教训"],
    [["V1 初始版","sink注册表+四优化层","过拟合59样本，三层失效","0.629","不要堆砌，不要在测试集上写规则"],
     ["V2 模块化","Ollama→GLM，四种模式","LLM杀TP，静态拦截F1=0","0.080","LLM只削误报不增TP"],
     ["V3 调参","放宽拦截+多温度","三把锁仍锁死，LLM零运行","0.077","静态拦截是最大损害"],
     ["V4 工具感知链","三工具+三Agent+后处理","RAG零贡献，A3架空A2","0.620","Checklist+工具信号=真正提升"]]);
  bigBl(s,0.7,3.55,8.6,1.65,[
    "从 V1 到 V4：盲目堆砌 → 模块拆解 → 放权 LLM → 工具感知——每个版本的失败都决定了下一版的方向",
    "V1 的 0.629 是过拟合假象，V4 的 0.620 是真正可泛化的性能。最终 PrimeVul 200 样本 F1=0.77",
  ],C.accent);
})();

// 48. Summary
(function(){
  const s=pres.addSlide();s.background={fill:C.primary};
  s.addText("总结",{x:0.7,y:0.6,w:3,h:0.5,fontSize:14,color:C.accent,fontFace:"Arial",bold:true});
  s.addText("从盲目堆砌到工具感知：\n每个版本的失败都在教我们下一步",{x:0.7,y:1.15,w:8.6,h:1.1,fontSize:26,color:C.white,fontFace:"Cambria",bold:true,lineSpacingMultiple:1.2});
  const pillars=[{t:"不堆砌",d:"四个优化层 → 模块化拆解\n每个组件独立验证有效性\n只保留经过消融证明的模块",c:C.danger},{t:"不拦截",d:"静态拦截 F1=0 → 完全放权 LLM\n静态分析只提供信号不做判决\n架构不能让主角站在门外",c:C.warning},{t:"不猜测",d:"通用 prompt → 六类 checklist\n逐项填表，消除 LLM 的模糊空间\n从"+q("可能")+"到"+q("是/否+行号"),c:C.success}];
  pillars.forEach(function(p,i){s.addShape(pres.shapes.ROUNDED_RECTANGLE,{x:0.7+i*3.1,y:2.7,w:2.8,h:1.25,fill:{color:"1A2D45"},rectRadius:0.08});s.addText(p.t,{x:0.85+i*3.1,y:2.8,w:2.5,h:0.35,fontSize:16,color:p.c,fontFace:"Arial",bold:true});s.addText(p.d,{x:0.85+i*3.1,y:3.2,w:2.5,h:0.6,fontSize:9.5,color:C.muted,fontFace:"Arial",lineSpacingMultiple:1.25});});
  s.addText("PrimeVul F1 = 0.77，零样本，超越微调基线",{x:0.7,y:4.25,w:6,h:0.45,fontSize:18,color:C.accent,fontFace:"Arial",bold:true});
  s.addText("谢谢！请各位老师批评指正",{x:0.7,y:4.85,w:8.6,h:0.3,fontSize:13,color:C.muted,fontFace:"Arial",align:"center"});
})();

// Save
const outPath=path.join(__dirname,"答辩PPT_代码审计.pptx");
pres.writeFile({fileName:outPath}).then(function(){console.log("PPT saved: "+outPath);console.log("Size: "+(fs.statSync(outPath).size/1024).toFixed(1)+" KB");}).catch(function(err){console.error("Error: "+err.message);process.exit(1);});
