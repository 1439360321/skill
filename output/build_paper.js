const docx = require("docx");
const fs = require("fs");

// Load content from JSON
const content = JSON.parse(
  fs.readFileSync("D:/project/skill/output/paper_content.json", "utf8")
);

const FONT = "SimSun";
const FONT_SIZE = 24;
const LINE_SPACING = 360;
const FONT_TITLE = 32;
const FONT_COVER = 28;
const COVER_TITLE_SIZE = 44;

const {
  Document, Paragraph, TextRun, HeadingLevel,
  AlignmentType, Packer, TableOfContents,
} = docx;

function p(text, opts) {
  opts = opts || {};
  return new Paragraph({
    children: [new TextRun({
      text: text, font: opts.font || FONT,
      size: opts.size || FONT_SIZE,
      bold: opts.bold || false,
    })],
    alignment: opts.alignment || AlignmentType.JUSTIFIED,
    spacing: { line: LINE_SPACING, after: opts.after || 0, before: opts.before || 0 },
    indent: opts.indent ? { firstLine: 480 } : undefined,
    heading: opts.heading,
  });
}

function titlePara(text, level) {
  return new Paragraph({
    children: [new TextRun({ text: text, font: "SimHei", size: FONT_TITLE, bold: true })],
    alignment: AlignmentType.CENTER,
    spacing: { line: LINE_SPACING, after: 200, before: 400 },
    heading: level,
  });
}

function coverLine(text, size) {
  return new Paragraph({
    children: [new TextRun({ text: text, font: FONT, size: size || FONT_COVER })],
    alignment: AlignmentType.CENTER,
    spacing: { line: 480, after: 100 },
  });
}

function emptyLine(n) {
  n = n || 1;
  return Array.from({ length: n }, function() {
    return new Paragraph({ children: [], spacing: { line: LINE_SPACING } });
  });
}

function indentP(text) {
  return p(text, { indent: true });
}

// Build cover
var cover = [
  emptyLine(3),
  new Paragraph({
    children: [new TextRun({ text: "网络空间安全应用联合大作业", font: "SimHei", size: 36, bold: true })],
    alignment: AlignmentType.CENTER,
    spacing: { line: 480, after: 200 },
  }),
  new Paragraph({
    children: [new TextRun({ text: "作品报告", font: "SimHei", size: 48, bold: true })],
    alignment: AlignmentType.CENTER,
    spacing: { line: 600, after: 400 },
  }),
  emptyLine(2),
  coverLine("作品名称：基于大语言模型的应用安全审计技术"),
  emptyLine(1),
  coverLine("学   号 ："),
  emptyLine(1),
  coverLine("姓   名 ："),
  emptyLine(1),
  coverLine("提交日期："),
  emptyLine(4),
].flat();

// TOC
var tocPage = [
  p("目     录", { alignment: AlignmentType.CENTER, size: FONT_TITLE, bold: true }),
  emptyLine(1),
  new TableOfContents("目录", { hyperlink: true, headingStyleRange: "1-3" }),
  emptyLine(2),
].flat();

// Abstract
var abstractSection = [
  titlePara("摘要", HeadingLevel.HEADING_1),
].concat(content.abstract.map(function(t) { return indentP(t); }))
 .concat(emptyLine(1));

// Chapter builder helpers
function buildChapter(ch) {
  var pages = [titlePara(ch.title, HeadingLevel.HEADING_1)];
  if (ch.intro) {
    pages.push(indentP(ch.intro));
  }
  for (var i = 0; i < ch.sections.length; i++) {
    var sec = ch.sections[i];
    addSection(sec, HeadingLevel.HEADING_2);
  }
  if (ch.paragraphs) {
    for (var j = 0; j < ch.paragraphs.length; j++) {
      pages.push(indentP(ch.paragraphs[j]));
    }
  }
  pages.push(emptyLine(1));
  return pages.flat();
}

function addSection(sec, level) {
  sectionPages.push(titlePara(sec.title, level));
  if (sec.paragraphs) {
    for (var k = 0; k < sec.paragraphs.length; k++) {
      sectionPages.push(indentP(sec.paragraphs[k]));
    }
  }
  if (sec.subsections) {
    for (var m = 0; m < sec.subsections.length; m++) {
      addSection(sec.subsections[m], HeadingLevel.HEADING_3);
    }
  }
}

var sectionPages;

function buildChapter1() {
  sectionPages = [];
  var ch = content.ch1;
  var pages = [titlePara(ch.title, HeadingLevel.HEADING_1)];
  for (var i = 0; i < ch.sections.length; i++) {
    var sec = ch.sections[i];
    addSection(sec, HeadingLevel.HEADING_2);
  }
  pages = pages.concat(sectionPages);
  pages.push(emptyLine(1));
  return pages.flat();
}

function buildChapter2() {
  sectionPages = [];
  var ch = content.ch2;
  var pages = [titlePara(ch.title, HeadingLevel.HEADING_1), indentP(ch.intro)];
  for (var i = 0; i < ch.sections.length; i++) {
    var sec = ch.sections[i];
    addSection(sec, HeadingLevel.HEADING_2);
  }
  pages = pages.concat(sectionPages);
  pages.push(emptyLine(1));
  return pages.flat();
}

function buildChapter3() {
  sectionPages = [];
  var ch = content.ch3;
  var pages = [titlePara(ch.title, HeadingLevel.HEADING_1)];
  for (var i = 0; i < ch.sections.length; i++) {
    var sec = ch.sections[i];
    addSection(sec, HeadingLevel.HEADING_2);
  }
  pages = pages.concat(sectionPages);
  pages.push(emptyLine(1));
  return pages.flat();
}

function buildChapter4() {
  var ch = content.ch4;
  var pages = [titlePara(ch.title, HeadingLevel.HEADING_1)];
  for (var i = 0; i < ch.paragraphs.length; i++) {
    pages.push(indentP(ch.paragraphs[i]));
  }
  pages.push(emptyLine(1));
  return pages.flat();
}

function buildChapter5() {
  sectionPages = [];
  var ch = content.ch5;
  var pages = [titlePara(ch.title, HeadingLevel.HEADING_1)];
  for (var i = 0; i < ch.sections.length; i++) {
    var sec = ch.sections[i];
    addSection(sec, HeadingLevel.HEADING_2);
  }
  pages = pages.concat(sectionPages);
  pages.push(emptyLine(1));
  return pages.flat();
}

function buildReferences() {
  var pages = [titlePara("参考文献", HeadingLevel.HEADING_1)];
  for (var i = 0; i < content.references.length; i++) {
    pages.push(p(content.references[i], { indent: false }));
  }
  pages.push(emptyLine(1));
  return pages.flat();
}

// Assemble document
var doc = new Document({
  styles: {
    default: {
      document: {
        run: { font: FONT, size: FONT_SIZE },
        paragraph: { spacing: { line: LINE_SPACING } },
      },
    },
  },
  sections: [
    { children: cover },
    { children: tocPage },
    { children: abstractSection },
    { children: buildChapter1() },
    { children: buildChapter2() },
    { children: buildChapter3() },
    { children: buildChapter4() },
    { children: buildChapter5() },
    { children: buildReferences() },
  ],
});

// Output
var outPath = "D:/project/skill/output/夏季学期报告_个人版.docx";
Packer.toBuffer(doc).then(function(buf) {
  fs.writeFileSync(outPath, buf);
  console.log("Done: " + outPath);
  console.log("Size: " + (buf.length / 1024).toFixed(1) + " KB");
});
