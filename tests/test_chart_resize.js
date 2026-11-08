const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(require('node:path').join(__dirname, '..', 'app', 'static', 'app.js'), 'utf8');
const drawChartSource = source.match(/function drawChart\([\s\S]+?(?=\nfunction drawLive)/)?.[0];
assert.ok(drawChartSource, 'drawChart function was not found');

const context = {
  devicePixelRatio: 1.25,
  fmtRate: String,
  colors: () => ({ grid: '#000', text: '#000', rx: '#000', tx: '#000' }),
};
vm.createContext(context);
vm.runInContext(drawChartSource, context);

const drawingContext = {
  scale() {}, beginPath() {}, moveTo() {}, lineTo() {}, stroke() {}, fillText() {}, fillRect() {},
};
let heightAttribute = '250';
const canvas = {
  dataset: {},
  style: {},
  getBoundingClientRect: () => ({ width: 800 }),
  getAttribute: name => name === 'height' ? heightAttribute : null,
  getContext: () => drawingContext,
  set height(value) { heightAttribute = String(value); },
  get height() { return Number(heightAttribute); },
  width: 0,
};

for (let iteration = 0; iteration < 20; iteration += 1) {
  context.drawChart(canvas, [], 'rx', 'tx', 'RX', 'TX');
  assert.equal(canvas.style.height, '250px');
  assert.equal(canvas.height, 313);
  assert.equal(canvas.dataset.logicalHeight, '250');
}

console.log('chart height remains stable across repeated high-DPI redraws');
