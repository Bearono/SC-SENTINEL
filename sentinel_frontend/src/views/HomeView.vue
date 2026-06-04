<template>
  <div class="page-home">
    <!-- HERO -->
    <div class="hero-wrap">
      <div class="orb orb1" /><div class="orb orb2" /><div class="orb orb3" />
      <div class="hero">
        <div>
          <div class="hbadge reveal"><span class="hbdot" />CISCN · Supply Chain Security</div>
          <h1 class="htitle reveal reveal-delay-1">LLM suspects.<br />eBPF <span class="accent">confirms.</span></h1>
          <p class="hdesc reveal reveal-delay-2">SENTINEL 是面向 C/C++ 开发者的供应链安全左移工具。Multi-Agent 静态语义审计发现可疑漏洞，AFL++ 模糊测试 + eBPF 内核级监控将推测转化为可触发的崩溃铁证。</p>
          <div class="hactions reveal reveal-delay-3">
            <button class="bp bw" style="padding:11px 26px;font-size:14px" @click="router.push('/submit')">Submit Project →</button>
            <button class="bp bg" style="padding:11px 26px;font-size:14px" @click="router.push('/history')">View History</button>
          </div>
          <p class="hnote reveal reveal-delay-4">支持 .zip 上传 · GitHub 链接 · Docker 隔离沙箱 · 自动销毁 · eBPF 内核透明监控</p>
        </div>
        <div class="dcard-wrap reveal reveal-delay-2">
          <div class="dcard">
            <div class="dctop">
              <div class="dctop-row">
                <span class="dcname">vulnerable_server.zip</span>
                <div class="dclive"><span class="dldot" />Fuzzing · 65%</div>
              </div>
              <div class="dstages">
                <div class="ds"><div class="dsico done">✓</div><div class="dsin"><div class="dsn">Agent A — Dependency Risk</div><div class="dss">libpng 1.6.34 · CVE-2018-13785</div></div></div>
                <div class="ds"><div class="dsico done">✓</div><div class="dsin"><div class="dsn">Agent B — Semantic Audit</div><div class="dss">找到 3 处 UAF / 1 处堆溢出</div></div></div>
                <div class="ds"><div class="dsico run">⬡</div><div class="dsin"><div class="dsn">AFL++ Fuzzing + eBPF Monitor</div><div class="dss">动态验证中 — 已捕获 2 次崩溃</div><div class="dspbar"><div class="dspfill" /></div></div></div>
                <div class="ds"><div class="dsico wait">◎</div><div class="dsin"><div class="dsn">Agent C — Report</div><div class="dss">等待验证完成</div></div></div>
              </div>
            </div>
            <div class="dcbody">
              <div class="dflabel">Confirmed Findings</div>
              <div class="dfrow"><span class="dftag">UAF</span><span class="dffile">parser.c:247</span><span class="dbadge b-ok">● eBPF Confirmed</span></div>
              <div class="dfrow"><span class="dftag">HEAP-OVF</span><span class="dffile">network.c:891</span><span class="dbadge b-cr">Critical</span></div>
              <div class="dfrow"><span class="dftag">DBL-FREE</span><span class="dffile">cache.c:134</span><span class="dbadge b-un">Verifying…</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- FEATURES -->
    <div class="feat-strip">
      <div class="feat-bg" />
      <div class="feat-inner">
        <div class="fitem reveal"><div class="fnum">0<sub>% false neg.</sub></div><div class="ftit">动态验证闭环</div><div class="fdesc">LLM 找嫌疑人，eBPF + AFL++ 出崩溃证据，每个 "confirmed" 漏洞都有内核级时间戳和内存地址作为铁证。</div></div>
        <div class="fitem reveal reveal-delay-1"><div class="fnum">4<sub> agents</sub></div><div class="ftit">Multi-Agent 架构</div><div class="fdesc">Agent A 识别第三方依赖 CVE，Agent B 审计源码语义，Agent C 汇总生成结构化报告与 PDF。</div></div>
        <div class="fitem reveal reveal-delay-2"><div class="fnum">∞<sub> isolated</sub></div><div class="ftit">Docker 隔离沙箱</div><div class="fdesc">每次 Fuzzing 在独立容器内执行，完成后自动销毁。eBPF 运行在内核层，对被测程序完全透明。</div></div>
      </div>
    </div>

    <!-- PIPELINE -->
    <div class="pipe-section">
      <div class="eyebrow reveal">How It Works</div>
      <h2 class="sec-h reveal reveal-delay-1">两阶段双机制，<em>从静态到内核</em></h2>
      <p class="sec-s reveal reveal-delay-2">Multi-Agent 静态审计 → 动态 AFL++ 验证 → eBPF 内核事件捕获，三层递进，证据链完整。</p>
      <div class="pipe-cards reveal reveal-delay-3">
        <div class="pc"><div class="pc-num">01</div><div class="pc-tag ta">Agent A</div><div class="pc-name">Dependency Risk</div><div class="pc-desc">识别 CMakeLists.txt 中第三方库，比对 NVD/OSV，输出 CVE 风险摘要。</div></div>
        <div class="pc"><div class="pc-num">02</div><div class="pc-tag ta">Agent B</div><div class="pc-name">Semantic Audit</div><div class="pc-desc">按函数粒度切片，识别 UAF / 堆溢出 / Double Free，输出漏洞位置和触发条件。</div></div>
        <div class="pc"><div class="pc-num">03</div><div class="pc-tag te">eBPF + AFL++</div><div class="pc-name">Dynamic Verify</div><div class="pc-desc">Docker 沙箱 AFL++ 模糊测试，uprobe 挂载 malloc/free，内核层捕获 UAF 事件。</div></div>
        <div class="pc"><div class="pc-num">04</div><div class="pc-tag tr">Agent C</div><div class="pc-name">Report Synthesis</div><div class="pc-desc">整合所有输出，生成含修复建议的 JSON 结构化报告与可下载 PDF。</div></div>
      </div>
    </div>

    <!-- COMPARE -->
    <div class="cmp-section">
      <div class="cmp-inner">
        <div class="eyebrow reveal">Why SENTINEL</div>
        <h2 class="sec-h reveal reveal-delay-1">不只是静态扫描，而是可触发的证据</h2>
        <p class="sec-s reveal reveal-delay-2" style="margin-bottom:40px">对比纯 LLM 代码审计，SENTINEL 在每个核心维度都提供了更强的保障</p>
        <table class="cmp-table reveal reveal-delay-3">
          <thead><tr><th>维度</th><th>纯 LLM 代码审计</th><th>SENTINEL</th></tr></thead>
          <tbody>
            <tr><td>结果可信度</td><td>LLM 推测，误报率高</td><td>动态验证后输出，附崩溃证据 <span class="tw-pill">✓</span></td></tr>
            <tr><td>分析视角</td><td>仅看源码文本</td><td>源码 + 运行时内核事件双视角 <span class="tw-pill">✓</span></td></tr>
            <tr><td>供应链感知</td><td>不感知依赖引入风险</td><td>识别第三方依赖 CVE 风险 <span class="tw-pill">✓</span></td></tr>
            <tr><td>eBPF 运用</td><td style="color:var(--fog)">无</td><td>uprobe 挂载 malloc/free，内核级观测 <span class="tw-pill">✓</span></td></tr>
            <tr><td>验证手段</td><td style="color:var(--fog)">无</td><td>AFL++ 模糊测试 + LLM Payload 生成 <span class="tw-pill">✓</span></td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()

function checkReveal() {
  document.querySelectorAll('.page-home .reveal').forEach((el) => {
    const r = el.getBoundingClientRect()
    if (r.top < window.innerHeight - 60) el.classList.add('in')
  })
}

onMounted(() => {
  setTimeout(checkReveal, 80)
  window.addEventListener('scroll', checkReveal, { passive: true })
})
onUnmounted(() => window.removeEventListener('scroll', checkReveal))
</script>

<style scoped>
.hero-wrap { position: relative; overflow: hidden; padding: 0 44px; }
.orb { position: absolute; border-radius: 50%; filter: blur(80px); opacity: .22; pointer-events: none; animation: od 12s ease-in-out infinite; }
.orb1 { width: 520px; height: 520px; background: radial-gradient(circle, #ff8c42, transparent 70%); top: -100px; right: 60px; }
.orb2 { width: 360px; height: 360px; background: radial-gradient(circle, #f7c665, transparent 70%); top: 220px; right: 360px; animation-delay: -4s; }
.orb3 { width: 260px; height: 260px; background: radial-gradient(circle, #ff6b35, transparent 70%); top: 60px; right: 500px; animation-delay: -8s; }
@keyframes od { 0%, 100% { transform: translate(0, 0) scale(1); } 33% { transform: translate(22px, -28px) scale(1.05); } 66% { transform: translate(-14px, 18px) scale(.97); } }
.hero { max-width: 1200px; margin: 0 auto; padding: 96px 0 88px; display: grid; grid-template-columns: 1fr 460px; gap: 72px; align-items: center; position: relative; z-index: 1; }
.hbadge { display: inline-flex; align-items: center; gap: 7px; padding: 5px 13px; border-radius: 9999px; border: 1px solid rgba(255, 107, 53, .3); background: rgba(255, 107, 53, .07); font-size: 11px; font-weight: 600; color: #c4430a; letter-spacing: .6px; text-transform: uppercase; margin-bottom: 28px; }
.hbdot { width: 6px; height: 6px; border-radius: 50%; background: var(--w1); animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: .4; transform: scale(.7); } }
.htitle { font-family: var(--fd); font-size: 62px; font-weight: 400; line-height: 1.04; letter-spacing: -1.2px; margin-bottom: 22px; }
.accent { background: linear-gradient(135deg, var(--w1) 0%, var(--amber) 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.hdesc { font-size: 15.5px; line-height: 1.7; color: var(--grv); max-width: 480px; margin-bottom: 36px; }
.hactions { display: flex; gap: 10px; align-items: center; }
.hnote { font-size: 11.5px; color: var(--fog); margin-top: 14px; }
/* CHUNK2 */
.dcard-wrap { perspective: 1200px; }
.dcard { background: #fff; border-radius: 22px; box-shadow: 0 2px 2px rgba(0, 0, 0, .04), 0 12px 40px rgba(0, 0, 0, .12), 0 0 0 1px rgba(0, 0, 0, .06); overflow: hidden; transform: rotateY(-4deg) rotateX(2deg); transition: transform .5s cubic-bezier(.22, 1, .36, 1); }
.dcard-wrap:hover .dcard { transform: rotateY(0deg) rotateX(0deg); }
.dctop { background: linear-gradient(160deg, #161210 0%, #2c2016 100%); padding: 18px 20px 14px; border-bottom: 1px solid rgba(255, 255, 255, .07); }
.dctop-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
.dcname { font-size: 13px; font-weight: 600; color: #fff; }
.dclive { display: flex; align-items: center; gap: 5px; font-size: 11px; color: rgba(255, 255, 255, .4); }
.dldot { width: 6px; height: 6px; border-radius: 50%; background: #34d399; animation: pulse 1.5s infinite; }
.dstages { padding: 4px 0 8px; }
.ds { display: flex; align-items: center; gap: 10px; padding: 7px 0; border-bottom: 1px solid rgba(255, 255, 255, .055); }
.ds:last-child { border-bottom: none; }
.dsico { width: 26px; height: 26px; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 11px; flex-shrink: 0; }
.dsico.done { background: linear-gradient(135deg, var(--w1), var(--amber)); color: #fff; }
.dsico.run { background: rgba(255, 255, 255, .1); color: rgba(255, 255, 255, .5); animation: blink 1.8s infinite; }
.dsico.wait { background: rgba(255, 255, 255, .05); color: rgba(255, 255, 255, .2); }
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }
.dsin { flex: 1; }
.dsn { font-size: 12px; font-weight: 500; color: rgba(255, 255, 255, .85); }
.dss { font-size: 11px; color: rgba(255, 255, 255, .36); margin-top: 1px; }
.dspbar { height: 2px; background: rgba(255, 255, 255, .08); border-radius: 9999px; margin-top: 5px; overflow: hidden; }
.dspfill { height: 100%; border-radius: 9999px; background: linear-gradient(90deg, var(--w1), var(--amber)); width: 65%; animation: grow 2s ease-out both; }
@keyframes grow { from { width: 0; } }
.dcbody { padding: 16px 20px 18px; }
.dflabel { font-size: 10px; font-weight: 700; letter-spacing: .6px; text-transform: uppercase; color: var(--fog); margin-bottom: 10px; }
.dfrow { display: flex; align-items: center; gap: 8px; padding: 7px 0; border-bottom: 1px solid var(--ch); font-size: 12px; }
.dfrow:last-child { border-bottom: none; }
.dftag { font-family: var(--fm); font-size: 10px; padding: 3px 7px; border-radius: 4px; background: var(--obs); color: #fff; flex-shrink: 0; }
.dffile { color: var(--grv); flex: 1; font-family: var(--fm); font-size: 11px; }
/* CHUNK3 */
.feat-strip { border-top: 1px solid var(--ch); position: relative; overflow: hidden; }
.feat-bg { position: absolute; inset: 0; background: linear-gradient(180deg, var(--w4) 0%, transparent 100%); opacity: .8; }
.feat-inner { max-width: 1200px; margin: 0 auto; padding: 64px 44px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 52px; position: relative; z-index: 1; }
.fnum { font-family: var(--fd); font-size: 44px; line-height: 1; margin-bottom: 10px; background: linear-gradient(135deg, var(--w1), var(--amber)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
.fnum sub { font-size: 15px; color: var(--grv); font-family: var(--fb); -webkit-text-fill-color: var(--grv); }
.ftit { font-size: 14px; font-weight: 600; margin-bottom: 6px; }
.fdesc { font-size: 13px; color: var(--grv); line-height: 1.6; }

.pipe-section { max-width: 1200px; margin: 0 auto; padding: 100px 44px; }
.eyebrow { font-size: 11px; font-weight: 700; letter-spacing: .8px; text-transform: uppercase; color: var(--w1); margin-bottom: 14px; }
.sec-h { font-family: var(--fd); font-size: 46px; letter-spacing: -.9px; line-height: 1.1; margin-bottom: 14px; }
.sec-h em { font-style: italic; color: var(--grv); }
.sec-s { font-size: 15px; color: var(--grv); max-width: 520px; margin-bottom: 56px; line-height: 1.65; }
.pipe-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: var(--ch); border-radius: 20px; overflow: hidden; box-shadow: var(--sc); }
.pc { background: #fff; padding: 28px 24px; position: relative; overflow: hidden; transition: all .25s; }
.pc::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--ch); transition: background .25s; }
.pc:hover::before { background: linear-gradient(90deg, var(--w1), var(--amber)); }
.pc:hover { background: var(--w4); }
.pc-num { font-family: var(--fd); font-size: 30px; color: var(--ch); margin-bottom: 14px; line-height: 1; }
.pc-tag { display: inline-flex; font-size: 10px; font-weight: 700; letter-spacing: .5px; text-transform: uppercase; padding: 3px 9px; border-radius: 9999px; margin-bottom: 14px; }
.ta { background: rgba(255, 107, 53, .1); color: #c4430a; }
.te { background: rgba(42, 95, 212, .1); color: #1a47b3; }
.tr { background: rgba(29, 138, 86, .1); color: #166842; }
.pc-name { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
.pc-desc { font-size: 12.5px; color: var(--grv); line-height: 1.55; }
/* CHUNK4 */
.cmp-section { background: var(--pw); border-top: 1px solid var(--ch); border-bottom: 1px solid var(--ch); padding: 100px 0; }
.cmp-inner { max-width: 1200px; margin: 0 auto; padding: 0 44px; }
.cmp-table { width: 100%; border-collapse: collapse; border-radius: 16px; overflow: hidden; box-shadow: var(--sc); }
.cmp-table th { text-align: left; padding: 13px 20px; border-bottom: 1px solid var(--ch); font-size: 11px; font-weight: 700; letter-spacing: .4px; background: #fff; }
.cmp-table th:last-child { background: linear-gradient(160deg, #161210, #2c2016); color: #fff; }
.cmp-table td { padding: 13px 20px; border-bottom: 1px solid var(--ch); color: var(--grv); }
.cmp-table td:first-child { color: var(--obs); font-weight: 500; }
.cmp-table td:last-child { background: rgba(255, 107, 53, .04); color: var(--obs); font-weight: 500; }
.cmp-table tr:last-child td { border-bottom: none; }
.cmp-table tr:hover td { background: rgba(255, 107, 53, .03); }
.cmp-table tr:hover td:last-child { background: rgba(255, 107, 53, .08); }
.tw-pill { display: inline-flex; align-items: center; gap: 4px; font-size: 11px; font-weight: 600; padding: 2px 9px; border-radius: 9999px; background: linear-gradient(135deg, var(--w1), var(--amber)); color: #fff; }

@media (max-width: 980px) {
  .hero { grid-template-columns: 1fr; gap: 48px; padding: 64px 0; }
  .htitle { font-size: 46px; }
  .feat-inner { grid-template-columns: 1fr; gap: 36px; }
  .pipe-cards { grid-template-columns: 1fr 1fr; }
  .sec-h { font-size: 34px; }
}
@media (max-width: 560px) {
  .pipe-cards { grid-template-columns: 1fr; }
}
</style>
