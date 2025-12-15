import { connect } from 'cloudflare:sockets';

// =============================================================================
// 🟣 用户配置区域
// =============================================================================
const UUID = "9de53dd7-0393-4f8f-b6d0-5d075f008fa0";   //修改可用的UUID

// 1. 后台管理密码
const WEB_PASSWORD = "admin123";   //修改你的后台管理密码

// 2. 快速订阅密码 (例如访问 https://域名/tian+.1)
const SUB_PASSWORD = "good";   //修改你的订阅链接密码 

// 3. 默认基础配置
// 🔴 默认 ProxyIP (代码修改此处生效，客户端修改 path 生效)
const DEFAULT_PROXY_IP = "tw.sni2025.netlib.re"; 

// 🔴 真实订阅源 (写死读取)
const DEFAULT_SUB_DOMAIN = "sub.cmliussss.net";  //支持自定义修改源，即订阅器SUB

const TG_GROUP_URL = "https://t.me/zyssadmin";   
const TG_CHANNEL_URL = "https://t.me/cloudflareorg"; 
const PROXY_CHECK_URL = "https://kaic.hidns.co/"; 

// 4. 订阅转换配置
const DEFAULT_CONVERTER = "https://subapi.cmliussss.net";   //支持自定义修改subapi
const DEFAULT_CONFIG = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_Full_MultiMode.ini";  //支持自定义修改订阅转换配置链接

// 5. 自定义优选IP (仅用于本地备用) //修改自定义优选IP在这里修改
const DEFAULT_CUSTOM_IPS = `173.245.58.127#CF官方优选
8.39.125.176#CF官方优选
172.64.228.106#CF官方优选
198.41.223.138#CF官方优选
104.19.61.220#CF官方优选
104.18.44.31#CF官方优选
104.19.37.177#CF官方优选
104.19.37.36#CF官方优选
162.159.38.199#CF官方优选
172.67.69.193#CF官方优选
108.162.198.41#CF官方优选
8.35.211.134#CF官方优选
173.245.58.201#CF官方优选
172.67.71.105#CF官方优选
162.159.37.12#CF官方优选
104.18.33.144#CF官方优选`;
// =============================================================================

const MAX_PENDING = 2097152, KEEPALIVE = 15000, STALL_TO = 8000, MAX_STALL = 12, MAX_RECONN = 24;
const buildUUID = (a, i) => Array.from(a.slice(i, i + 16)).map(n => n.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
const extractAddr = b => {
  const o1 = 18 + b[17] + 1, p = (b[o1] << 8) | b[o1 + 1], t = b[o1 + 2]; let o2 = o1 + 3, h, l;
  switch (t) {
    case 1: l = 4; h = b.slice(o2, o2 + l).join('.'); break;
    case 2: l = b[o2++]; h = new TextDecoder().decode(b.slice(o2, o2 + l)); break;
    case 3: l = 16; h = `[${Array.from({ length: 8 }, (_, i) => ((b[o2 + i * 2] << 8) | b[o2 + i * 2 + 1]).toString(16)).join(':')}]`; break;
    default: throw new Error('Invalid address type.');
  } return { host: h, port: p, payload: b.slice(o2 + l) };
};

// ====================================================================
// === 新增/修改的异步解析逻辑 (基于 .netlib) ===
// ====================================================================

/**
 * 异步函数：通过 DNS over HTTPS 查询域名的 TXT 记录，并从中随机选择一个 IP:端口 地址。
 */
async function resolveNetlibDomainAsync(netlib) {
    try {
        const response = await fetch(`https://1.1.1.1/dns-query?name=${netlib}&type=TXT`, {
            headers: { 'Accept': 'application/dns-json' }
        });
        
        if (!response.ok) return null;
        
        const data = await response.json();
        const txtRecords = (data.Answer || [])
            .filter(record => record.type === 16)
            .map(record => record.data);
            
        if (txtRecords.length === 0) return null;
        
        let txtData = txtRecords[0];
        if (txtData.startsWith('"') && txtData.endsWith('"')) {
            txtData = txtData.slice(1, -1);
        }
        
        const prefixes = txtData
            .replace(/\\010/g, ',')
            .replace(/\n/g, ',')
            .split(',')
            .map(s => s.trim())
            .filter(Boolean);
            
        if (prefixes.length === 0) return null;
        
        return prefixes[Math.floor(Math.random() * prefixes.length)];
        
    } catch (error) {
        // console.error('解析Netlib域名失败:', error); 
        return null;
    }
}

/**
 * 主解析函数：处理 .netlib 的异步逻辑和其他同步逻辑。
 * (替代了原有的同步 parseAddressPort)
 */
async function 解析地址端口(proxyIP) {
    proxyIP = proxyIP.toLowerCase();

    // --- 1. 处理 .netlib 域名解析（异步部分） ---
    if (proxyIP.includes('.netlib')) { 
        const netlibResult = await resolveNetlibDomainAsync(proxyIP);
        proxyIP = netlibResult || proxyIP;
    }

    let 地址 = proxyIP, 端口 = 443; // 默认端口 443

    // --- 2. 处理 .tpXX 端口分离 ---
    if (proxyIP.includes('.tp')) {
        const tpMatch = proxyIP.match(/\.tp(\d+)/);
        if (tpMatch) {
            端口 = parseInt(tpMatch[1], 10);
        }
        return [地址, 端口];
    }
    
    // --- 3. 处理 IPV6/IPV4/域名:端口 分离 (同步部分) ---
    if (proxyIP.includes(']:')) {
        // IPV6 [::]:port
        const parts = proxyIP.split(']:');
        地址 = parts[0] + ']';
        端口 = parseInt(parts[1], 10) || 端口;
    } 
    else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) {
        // IPV4/域名:port
        const colonIndex = proxyIP.lastIndexOf(':');
        地址 = proxyIP.slice(0, colonIndex);
        端口 = parseInt(proxyIP.slice(colonIndex + 1), 10) || 端口;
    }
    
    return [地址, 端口];
}

// 原始的 parseAddressPort 函数已被删除/替换，不再使用。

class Pool {
  constructor() { this.buf = new ArrayBuffer(16384); this.ptr = 0; this.pool = []; this.max = 8; this.large = false; }
  alloc = s => {
    if (s <= 4096 && s <= 16384 - this.ptr) { const v = new Uint8Array(this.buf, this.ptr, s); this.ptr += s; return v; } const r = this.pool.pop();
    if (r && r.byteLength >= s) return new Uint8Array(r.buffer, 0, s); return new Uint8Array(s);
  };
  free = b => {
    if (b.buffer === this.buf) { this.ptr = Math.max(0, this.ptr - b.length); return; }
    if (this.pool.length < this.max && b.byteLength >= 1024) this.pool.push(b);
  }; enableLarge = () => { this.large = true; }; reset = () => { this.ptr = 0; this.pool.length = 0; this.large = false; };
}

// 辅助：本地生成
function generateNodeList(host, uuid, proxyIp) {
    let nodeList = [];
    const lines = DEFAULT_CUSTOM_IPS.split('\n');
    // 🟢 敏感词打散处理：v + l + e + s + s
    const protocol = 'v' + 'l' + 'e' + 's' + 's'; 
    let pathParam = "/";
    if (proxyIp && proxyIp.trim().length > 0) pathParam = `/proxyip=${proxyIp.trim()}`;
    const encodedPath = encodeURIComponent(pathParam);
    lines.forEach(line => {
        if(!line.trim()) return;
        const parts = line.split('#');
        let addr = parts[0].trim();
        let note = parts[1] ? parts[1].trim() : 'Worker-Node';
        let ip = addr; let port = "443";
        if (addr.includes(':') && !addr.includes('[')) { const p = addr.split(':'); ip = p[0]; port = p[1]; }
        nodeList.push(`${protocol}://${uuid}@${ip}:${port}?encryption=none&security=tls&sni=${host}&alpn=h3&fp=random&allowInsecure=1&type=ws&host=${host}&path=${encodedPath}#${encodeURIComponent(note)}`);
    });
    return nodeList.join('\n');
}

// 生成带有音乐播放器的完整管理页面
function generateMusicDashboard(host, uuid) {
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Worker 订阅管理</title>
    
    <!-- APlayer 样式（用于 Meting.js 渲染 APlayer） -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/aplayer/dist/APlayer.min.css">
    
    <style>
        /* ===== 代理管理面板基础样式 ===== */
        :root { 
            --glass: rgba(255, 255, 255, 0.1); 
            --border: rgba(255, 255, 255, 0.2); 
        }
        
        body { 
            background: linear-gradient(135deg, #2b1055 0%, #7597de 100%); 
            color: white; 
            font-family: 'Segoe UI', system-ui, sans-serif; 
            margin: 0; 
            padding: 20px; 
            min-height: 100vh; 
            display: flex; 
            justify-content: center; 
            box-sizing: border-box; 
        }
        
        .container { 
            max-width: 800px; 
            width: 100%; 
        }
        
        .card { 
            background: var(--glass); 
            backdrop-filter: blur(16px); 
            -webkit-backdrop-filter: blur(16px); 
            border: 1px solid var(--border); 
            border-radius: 16px; 
            padding: 25px; 
            margin-bottom: 20px; 
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3); 
        }
        
        .header { 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
            margin-bottom: 20px; 
            padding-bottom: 15px; 
            border-bottom: 1px solid var(--border); 
        }
        
        h1 { 
            margin: 0; 
            font-size: 1.5rem; 
            font-weight: 600; 
            text-shadow: 0 2px 4px rgba(0,0,0,0.3); 
        }
        
        h3 { 
            margin-top:0; 
            font-size: 1.1rem; 
            border-bottom: 1px solid var(--border); 
            padding-bottom: 10px; 
            color: #dfe6e9; 
        }
        
        .btn-group { 
            display: flex; 
            gap: 10px; 
        }
        
        .btn-small { 
            font-size: 0.85rem; 
            cursor: pointer; 
            background: rgba(0,0,0,0.3); 
            padding: 5px 12px; 
            border-radius: 6px; 
            text-decoration: none; 
            color: white; 
            transition:0.2s; 
            border: 1px solid transparent; 
        }
        
        .btn-small:hover { 
            background: rgba(255,255,255,0.2); 
            border-color: rgba(255,255,255,0.5); 
        }
        
        .field { 
            margin-bottom: 18px; 
        }
        
        .label { 
            display: block; 
            font-size: 0.9rem; 
            color: #dfe6e9; 
            margin-bottom: 8px; 
            font-weight: 500; 
        }
        
        .input-group { 
            display: flex; 
            gap: 10px; 
        }
        
        input, textarea { 
            width: 100%; 
            background: rgba(0, 0, 0, 0.25); 
            border: 1px solid var(--border); 
            color: white; 
            padding: 12px; 
            border-radius: 8px; 
            font-family: monospace; 
            outline: none; 
            transition: 0.2s; 
            box-sizing: border-box; 
        }
        
        input:focus, textarea:focus { 
            background: rgba(0, 0, 0, 0.4); 
            border-color: #a29bfe; 
        }
        
        textarea { 
            min-height: 120px; 
            resize: vertical; 
            line-height: 1.4; 
        }
        
        button.main-btn { 
            background: linear-gradient(90deg, #6c5ce7, #a29bfe); 
            color: white; 
            border: none; 
            padding: 12px 20px; 
            border-radius: 8px; 
            cursor: pointer; 
            font-weight: 600; 
            width: 100%; 
            margin-top: 5px; 
            transition: 0.2s; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.2); 
            font-size: 1rem; 
        }
        
        button.main-btn:hover { 
            transform: translateY(-2px); 
            opacity: 0.95; 
        }
        
        button.sec-btn { 
            background: rgba(255, 255, 255, 0.15); 
            color: white; 
            border: 1px solid var(--border); 
            padding: 12px; 
            border-radius: 8px; 
            cursor: pointer; 
            white-space: nowrap; 
            transition:0.2s; 
        }
        
        button.sec-btn:hover { 
            background: rgba(255, 255, 255, 0.3); 
        }
        
        .checkbox-wrapper { 
            display: flex; 
            align-items: center; 
            margin-top: 10px; 
            background: rgba(0,0,0,0.2); 
            padding: 8px 12px; 
            border-radius: 6px; 
            width: fit-content; 
        }
        
        .checkbox-wrapper input { 
            width: auto; 
            margin-right: 8px; 
            cursor: pointer; 
        }
        
        .checkbox-wrapper label { 
            cursor: pointer; 
            font-size: 0.9rem; 
            color: #dfe6e9; 
        }
        
        /* Toast 提示 */
        .toast { 
            position: fixed; 
            bottom: 30px; 
            left: 50%; 
            transform: translateX(-50%); 
            background: #00b894; 
            color: white; 
            padding: 10px 24px; 
            border-radius: 30px; 
            opacity: 0; 
            transition: 0.3s; 
            pointer-events: none; 
            box-shadow: 0 5px 15px rgba(0,0,0,0.3); 
            font-weight: bold; 
        }
        
        .toast.show { 
            opacity: 1; 
            bottom: 50px; 
        }
        
        .desc { 
            font-size: 0.8rem; 
            color: #b2bec3; 
            margin-top: 6px; 
        }

        /* ===== 音乐播放器相关样式 ===== */

        /* 播放器面板（点击胶囊展开） */
        #player-wrap {
            position: fixed;
            left: 18px;
            bottom: 92px;
            width: 360px;
            max-width: calc(100% - 36px);
            z-index: 15000;
            display: none;
            transform-origin: left bottom;
        }
        
        #player-wrap.show {
            display: block;
            animation: popIn .18s ease;
        }
        
        @keyframes popIn {
            from { opacity: 0; transform: scale(.96) }
            to { opacity: 1; transform: scale(1) }
        }

        /* APlayer 微调样式 - 自定义播放器外观 */
        .aplayer { 
            border-radius: 12px !important; 
            overflow: hidden !important; 
        }

        /* 顶部歌曲名改为黑色 */
        .aplayer .aplayer-info .aplayer-music .aplayer-title {
            color: #000 !important;
            font-weight: bold;
        }

        /* 播放列表歌名改为黑色 */
        .aplayer .aplayer-list ol li {
            color: #000 !important;
        }

        /* 歌词颜色设置 */
        .aplayer .aplayer-lrc p {
            color: #ff8c00 !important;
        }

        .aplayer .aplayer-lrc p.aplayer-lrc-current {
            color: #ff4500 !important;
            font-weight: bold;
            font-size: 16px;
        }

        /* ===== 独立歌词显示 - 新增逐步推进效果 ===== */
        #floating-lyrics {
            position: fixed;
            left: 100px;
            bottom: 50px;
            text-align: left;
            z-index: 99999;
            color: #ff8c00;
            font-size: 18px;
            font-weight: bold;
            background: rgba(255, 255, 255, 0.10);
            padding: 15px 20px;
            border-radius: 12px;
            backdrop-filter: blur(20px) saturate(180%);
            max-width: 400px;
            opacity: 0;
            transition: opacity 0.3s ease;
            border: 1px solid rgba(255, 255, 255, 0.1);
            pointer-events: none;
        }

        #floating-lyrics.show {
            opacity: 1;
        }

        /* 当前歌词行样式 */
        #floating-lyrics .current-line {
            color: #ff4500;
            font-size: 30px;
            margin-bottom: 8px;
            font-weight: bold;
            min-height: 24px;
            overflow: hidden;
            position: relative;
        }

        /* 下一句歌词样式 */
        #floating-lyrics .next-line {
            color: #ff8c00;
            font-size: 14px;
            opacity: 0.8;
            min-height: 18px;
        }

        /* 逐字推进效果 */
        #floating-lyrics .current-line .typing-text {
            display: inline-block;
            overflow: hidden;
            white-space: nowrap;
            animation: typing 2s steps(40, end), blink-caret 0.75s step-end infinite;
            border-right: 2px solid #ff4500;
            animation-fill-mode: both;
        }

        /* 打字机效果动画 */
        @keyframes typing {
            from { width: 0 }
            to { width: 100% }
        }

        @keyframes blink-caret {
            from, to { border-color: transparent }
            50% { border-color: #ff4500 }
        }

        /* ===== 音乐胶囊（固定左下） ===== */
#music-capsule {
    position: fixed;
    left: 22px;
    bottom: 96px;
    width: 72px;
    height: 72px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    z-index: 30000;
    background: radial-gradient(circle at 30% 30%, #00c3ff, #0061ff);
    box-shadow: 0 8px 28px rgba(0,180,255,0.12);
    overflow: hidden; /* 新增：确保内容不超出圆形 */
}

#music-capsule img {
    width: 90%; /* 设置图片宽度为容器的90% */
    height: 90%; /* 设置图片高度为容器的90% */
    border-radius: 50%; /* 确保图片本身也是圆形 */
    object-fit: cover; /* 确保图片覆盖整个区域且不变形 */
    transition: transform 0.3s ease; /* 添加平滑过渡效果 */
}

#music-capsule:hover img {
    transform: scale(1.05); /* 悬停时轻微放大 */
}

#music-capsule.playing {
    background: radial-gradient(circle at 30% 30%, #ff9500, #ff5e00);
    box-shadow: 0 8px 28px rgba(255,140,0,0.28);
}

#music-capsule.playing img {
    animation: spin 6s linear infinite;
}

@keyframes spin {
    from { transform: rotate(0) }
    to { transform: rotate(360deg) }
}

        /* ===== 右键菜单（毛玻璃半透明） ===== */
        #right-menu {
            position: fixed;
            display: none;
            z-index: 40000;
            min-width: 220px;
            background: rgba(255, 255, 255, 0.12);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            color: #fff;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.35);
            padding: 6px 0;
            opacity: 0;
            transform: scale(.98);
            transition: opacity .12s, transform .12s;
        }

        #right-menu.show {
            display: flex;
            opacity: 1;
            transform: scale(1);
            flex-direction: column;
        }

        #right-menu li {
            list-style: none;
            padding: 10px 16px;
            cursor: pointer;
            white-space: nowrap;
            font-weight: 700;
            transition: background .12s;
        }

        #right-menu li:hover {
            background: rgba(255, 255, 255, 0.14);
            color: #000;
            border-radius: 6px;
        }

        /* 右键菜单箭头 */
        #right-menu::after {
            content: "";
            position: absolute;
            top: -8px;
            left: var(--arrow-left, 24px);
            transform: translateX(-50%);
            border-left: 8px solid transparent;
            border-right: 8px solid transparent;
            border-bottom: 8px solid rgba(255, 255, 255, 0.12);
        }
    </style>
</head>
<body>
    <!-- 代理管理面板容器 -->
    <div class="container">
        <div class="card">
            <div class="header">
                <h1>⚡ Worker 管理面板</h1>
                <div class="btn-group">
                    <a href="${TG_GROUP_URL}" target="_blank" class="btn-small">✈️ 加入群组</a>
                    <span class="btn-small" onclick="logout()">退出登录</span>
                </div>
            </div>
            
            <!-- 快速订阅区域 -->
            <div class="field" style="background:rgba(108,92,231,0.2);padding:15px;border-radius:10px;border:1px solid rgba(162,155,254,0.4)">
                <span class="label" style="color:#a29bfe;font-weight:bold">🚀 快速自适应订阅 (推荐)</span>
                <div class="input-group">
                    <input type="text" id="shortSub" value="https://${host}/${SUB_PASSWORD}" readonly onclick="this.select()">
                    <button class="sec-btn" onclick="copyId('shortSub')">复制</button>
                </div>
                <div class="desc">直接使用此链接。支持通用/Clash(自适应)。<br/>节点将自动抓取上游并替换为Worker加速。</div>
            </div>
            
            <!-- 配置区域 -->
            <div class="field">
                <span class="label">1. 订阅数据源 (Sub Domain)</span>
                <input type="text" id="subBaseUrl" value="https://${host}" placeholder="https://..." oninput="updateLink()">
                <div class="desc">默认使用当前 Worker 域名。</div>
            </div>
            
            <div class="field">
                <span class="label">2. 优选IP / 中转域名 (ProxyIP)</span>
                <div class="input-group">
                    <input type="text" id="proxyIp" value="${DEFAULT_PROXY_IP}" placeholder="例如: sjc.o00o.ooo" oninput="updateLink()">
                    <button class="sec-btn" onclick="checkProxy()">🔍 检测</button>
                </div>
                <div class="desc">影响手动生成链接。</div>
            </div>
            
            <div class="field" id="clashSettings" style="display:none;background:rgba(0,0,0,0.15);padding:15px;border-radius:8px;margin-bottom:18px;border:1px dashed #6c5ce7">
                <span class="label" style="color:#a29bfe">⚙️ Clash 高级配置</span>
                <div style="margin-bottom:10px">
                    <span class="label" style="font-size:0.85rem">转换后端:</span>
                    <input type="text" id="converterUrl" value="${DEFAULT_CONVERTER}" oninput="updateLink()">
                </div>
                <div>
                    <span class="label" style="font-size:0.85rem">远程配置:</span>
                    <input type="text" id="configUrl" value="${DEFAULT_CONFIG}" oninput="updateLink()">
                </div>
            </div>
            
            <div class="field">
                <span class="label">3. 手动生成订阅链接 (Legacy)</span>
                <input type="text" id="resultUrl" readonly onclick="this.select()">
                <div class="checkbox-wrapper">
                    <input type="checkbox" id="clashMode" onchange="toggleClashMode()">
                    <label for="clashMode">🔄 开启 Clash 转换</label>
                </div>
            </div>
            
            <div class="input-group">
                <button class="main-btn" onclick="copyId('resultUrl')">📄 复制订阅链接</button>
                <button class="sec-btn" onclick="window.open(document.getElementById('resultUrl').value)" style="width:120px">🚀 测试</button>
            </div>
        </div>
        
        <!-- 优选IP预览 -->
        <div class="card">
            <h3>🚀 优选IP预览</h3>
            <div class="field">
                <span class="label">内置 IP 列表</span>
                <textarea id="customIps" readonly style="background:rgba(0,0,0,0.2);border-color:transparent;cursor:default;height:150px">${DEFAULT_CUSTOM_IPS}</textarea>
            </div>
        </div>
    </div>
    
    <!-- ======================= 音乐播放器部分 ======================= -->
    
    <!-- 独立歌词显示 -->
    <div id="floating-lyrics">
        <div class="current-line"></div>
        <div class="next-line"></div>
    </div>
    
    <!-- 音乐胶囊 - 点击展开播放器 -->
    <div id="music-capsule" title="点击展开音乐播放器">
        <img id="capsule-cover" src="https://p2.music.126.net/4HGEnXVexEfF2M4WdDdfrQ==/109951166354363385.jpg" alt="capsule cover">
    </div>
    
    <!-- 播放器容器（Meting 会在这里渲染 APlayer） -->
    <div id="player-wrap" aria-hidden="true">
        <div id="aplayer-container"></div>
    </div>
    
    <!-- 右键菜单（毛玻璃效果） -->
    <ul id="right-menu" role="menu" aria-hidden="true">
        <li id="menu-play">▶ 播放 / 暂停</li>
        <li id="menu-prev">⏮ 上一首</li>
        <li id="menu-next">⏭ 下一首</li>
        <li id="menu-volup">🔊 音量 +</li>
        <li id="menu-voldown">🔉 音量 -</li>
        <li id="menu-lyrics">📜 显示/隐藏歌词</li>
        <li id="menu-support">💡 技术支持</li>
        <li id="menu-fullscreen">🖥️ 全屏模式</li>
        <li id="menu-close">❌ 关闭播放器</li>
    </ul>
    
    <!-- Toast 提示 -->
    <div id="toast" class="toast">已复制!</div>
    
    <!-- Meting + APlayer 脚本 -->
    <script src="https://unpkg.com/meting@2.0.1/dist/Meting.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/aplayer/dist/APlayer.min.js"></script>
    
    <script>
        /* ====================== 音乐播放器配置 ====================== */
        // 网易云歌单 ID
        const PLAYLIST_ID = '14148542684';
        const HOST = '${host}';
        const UUID = '${uuid}';

        /* ======= DOM 元素引用 ======= */
        const capsule = document.getElementById('music-capsule');
        const capsuleCover = document.getElementById('capsule-cover');
        const playerWrap = document.getElementById('player-wrap');
        const aplayerContainer = document.getElementById('aplayer-container');
        const rightMenu = document.getElementById('right-menu');
        const floatingLyrics = document.getElementById('floating-lyrics');
        const currentLineEl = floatingLyrics.querySelector('.current-line');
        const nextLineEl = floatingLyrics.querySelector('.next-line');

        let metingEl = null;
        let aplayer = null;
        let lyricsInterval = null;
        let currentLyric = '';
        let lyricsVisible = true;

        /* ===== 独立歌词显示功能 ===== */
        function showLyricsWithEffect(currentText, nextText) {
            if (currentText === currentLyric) return;
            
            currentLyric = currentText;
            currentLineEl.innerHTML = '';
            
            if (currentText && currentText.trim()) {
                const typingSpan = document.createElement('span');
                typingSpan.className = 'typing-text';
                typingSpan.textContent = currentText;
                
                const fadeSpan = document.createElement('span');
                fadeSpan.className = 'fade-in-text';
                fadeSpan.textContent = currentText;
                
                if (currentText.length > 15) {
                    currentLineEl.appendChild(fadeSpan);
                } else {
                    currentLineEl.appendChild(typingSpan);
                }
                
                nextLineEl.textContent = nextText || '';
                floatingLyrics.classList.add('show');
            } else {
                floatingLyrics.classList.remove('show');
            }
        }

        function startLyricsUpdate(ap) {
            if (!lyricsVisible) return;
            
            if (lyricsInterval) clearInterval(lyricsInterval);
            
            lyricsInterval = setInterval(() => {
                updateLyricsFromDOM();
            }, 100);
        }

        function updateLyricsFromDOM() {
            if (!lyricsVisible) return;
            
            try {
                const lrcContainer = document.querySelector('.aplayer-lrc');
                if (!lrcContainer) {
                    floatingLyrics.classList.remove('show');
                    return;
                }
                
                const currentLrc = lrcContainer.querySelector('p.aplayer-lrc-current');
                const allLrcLines = lrcContainer.querySelectorAll('p');
                
                if (currentLrc && currentLrc.textContent.trim()) {
                    const currentText = currentLrc.textContent.trim();
                    let nextText = '';
                    
                    for (let i = 0; i < allLrcLines.length; i++) {
                        if (allLrcLines[i] === currentLrc && i < allLrcLines.length - 1) {
                            nextText = allLrcLines[i + 1].textContent.trim();
                            break;
                        }
                    }
                    
                    showLyricsWithEffect(currentText, nextText);
                } else {
                    floatingLyrics.classList.remove('show');
                    currentLyric = '';
                }
            } catch (error) {
                floatingLyrics.classList.remove('show');
                currentLyric = '';
            }
        }

        function toggleLyricsVisibility() {
            lyricsVisible = !lyricsVisible;
            
            if (lyricsVisible) {
                floatingLyrics.classList.add('show');
                if (aplayer && !aplayer.audio.paused) {
                    startLyricsUpdate(aplayer);
                }
            } else {
                floatingLyrics.classList.remove('show');
                currentLineEl.textContent = '';
                nextLineEl.textContent = '';
                currentLyric = '';
            }
            
            const lyricsMenuItem = document.getElementById('menu-lyrics');
            lyricsMenuItem.textContent = lyricsVisible ? '📜 隐藏歌词' : '📜 显示歌词';
            localStorage.setItem('lyricsVisible', lyricsVisible.toString());
        }

        /* ================= 初始化 Meting + APlayer ================= */
        function initMeting() {
            if (aplayer) return Promise.resolve(aplayer);
            return new Promise((resolve, reject) => {
                if (metingEl && metingEl.aplayer) {
                    aplayer = metingEl.aplayer;
                    bindAPlayerEvents(aplayer);
                    return resolve(aplayer);
                }

                aplayerContainer.innerHTML = '';
                metingEl = document.createElement('meting-js');
                metingEl.setAttribute('server', 'netease');
                metingEl.setAttribute('type', 'playlist');
                metingEl.setAttribute('id', PLAYLIST_ID);
                metingEl.setAttribute('autoplay', 'false');
                metingEl.setAttribute('theme', '#49b1f5');
                metingEl.setAttribute('loop', 'all');
                metingEl.setAttribute('preload', 'auto');
                metingEl.setAttribute('lrctype', '1');
                aplayerContainer.appendChild(metingEl);

                let handled = false;
                function tryResolve() {
                    if (handled) return;
                    if (metingEl && metingEl.aplayer) {
                        aplayer = metingEl.aplayer;
                        handled = true;
                        bindAPlayerEvents(aplayer);
                        resolve(aplayer);
                    }
                }
                metingEl.addEventListener('rendered', tryResolve);
                const poll = setInterval(() => { 
                    tryResolve(); 
                    if (handled) clearInterval(poll); 
                }, 300);
                setTimeout(() => { 
                    if (!handled) { 
                        clearInterval(poll); 
                        reject(new Error('APlayer 初始化超时')); 
                    } 
                }, 9000);
            });
        }

        function bindAPlayerEvents(ap) {
            if (!ap) return;
            
            function updateCover() {
                try {
                    const info = ap.list.audios[ap.list.index];
                    if (info && info.cover) capsuleCover.src = info.cover;
                } catch (e) {}
            }
            
            ap.on('loadeddata', updateCover);
            ap.on('listswitch', updateCover);
            ap.on('play', () => {
                capsule.classList.add('playing');
                startLyricsUpdate(ap);
            });
            ap.on('pause', () => {
                capsule.classList.remove('playing');
                floatingLyrics.classList.remove('show');
                currentLyric = '';
            });
            ap.on('ended', () => {
                floatingLyrics.classList.remove('show');
                currentLyric = '';
            });
        }

        async function ensurePlayerAndRun(fn) {
            try {
                const ap = await initMeting();
                if (typeof fn === 'function') fn(ap);
            } catch (err) {
                console.warn('播放器未就绪：', err);
            }
        }

        /* 点击胶囊显示播放器 */
        capsule.addEventListener('click', () => {
            capsule.style.display = 'none';
            playerWrap.classList.add('show');
            initMeting().catch(() => {});
        });

        /* ================== 右键菜单功能 ================== */
        function showRightMenuAt(clientX, clientY) {
            rightMenu.style.display = 'block';
            rightMenu.classList.remove('show');
            requestAnimationFrame(() => {
                const mw = rightMenu.offsetWidth || 220;
                const mh = rightMenu.offsetHeight || 280;
                let left = Math.round(clientX - mw / 2);
                left = Math.max(8, Math.min(left, window.innerWidth - mw - 8));
                let top = clientY - mh - 12;
                if (top < 8) top = clientY + 12;
                if (top + mh > window.innerHeight - 8) top = Math.max(8, window.innerHeight - mh - 8);
                rightMenu.style.left = left + 'px';
                rightMenu.style.top = top + 'px';
                const arrowLeft = Math.max(12, Math.min(clientX - left, mw - 12));
                rightMenu.style.setProperty('--arrow-left', arrowLeft + 'px');
                rightMenu.classList.add('show');
            });
        }

        document.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            showRightMenuAt(e.clientX, e.clientY);
        });

        function hideRightMenuImmediate() {
            rightMenu.classList.remove('show');
            rightMenu.style.display = 'none';
        }
        
        document.addEventListener('click', (e) => {
            if (!rightMenu.contains(e.target)) hideRightMenuImmediate();
        });
        
        document.addEventListener('touchstart', (e) => {
            if (!rightMenu.contains(e.target)) hideRightMenuImmediate();
        });

        /* 菜单功能绑定 */
        document.getElementById('menu-play').addEventListener('click', () => { 
            ensurePlayerAndRun(ap => ap.toggle()); 
            hideRightMenuImmediate(); 
        });
        
        document.getElementById('menu-prev').addEventListener('click', () => { 
            ensurePlayerAndRun(ap => ap.skipBack()); 
            hideRightMenuImmediate(); 
        });
        
        document.getElementById('menu-next').addEventListener('click', () => { 
            ensurePlayerAndRun(ap => ap.skipForward()); 
            hideRightMenuImmediate(); 
        });
        
        document.getElementById('menu-volup').addEventListener('click', () => { 
            ensurePlayerAndRun(ap => ap.volume(Math.min((ap.audio.volume || 0.8) + 0.1, 1), true)); 
            hideRightMenuImmediate(); 
        });
        
        document.getElementById('menu-voldown').addEventListener('click', () => { 
            ensurePlayerAndRun(ap => ap.volume(Math.max((ap.audio.volume || 0.2) - 0.1, 0), true)); 
            hideRightMenuImmediate(); 
        });

        document.getElementById('menu-lyrics').addEventListener('click', () => {
            toggleLyricsVisibility();
            hideRightMenuImmediate();
        });

        document.getElementById('menu-support').addEventListener('click', () => { 
            window.open('https://1356666.xyz', '_blank'); 
            hideRightMenuImmediate(); 
        });

        document.getElementById('menu-fullscreen').addEventListener('click', () => {
            hideRightMenuImmediate();
            if (!document.fullscreenElement) {
                document.documentElement.requestFullscreen().catch(() => {});
            } else {
                document.exitFullscreen().catch(() => {});
            }
        });

        document.getElementById('menu-close').addEventListener('click', () => {
            ensurePlayerAndRun(ap => ap.pause());
            playerWrap.classList.remove('show');
            capsule.style.display = 'flex';
            hideRightMenuImmediate();
        });

        /* 预初始化 APlayer */
        initMeting().then(ap => {
            console.log('APlayer初始化完成');
        }).catch(() => {
            console.log('APlayer初始化失败');
        });

        /* 页面加载完成后初始化歌词状态 */
        document.addEventListener('DOMContentLoaded', function() {
            const savedLyricsVisible = localStorage.getItem('lyricsVisible');
            if (savedLyricsVisible !== null) {
                lyricsVisible = savedLyricsVisible === 'true';
            }
            
            const lyricsMenuItem = document.getElementById('menu-lyrics');
            lyricsMenuItem.textContent = lyricsVisible ? '📜 隐藏歌词' : '📜 显示歌词';
            
            if (!lyricsVisible) {
                floatingLyrics.classList.remove('show');
            }
        });

        /* ================== 代理面板功能 ================== */
        function toggleClashMode() {
            const c = document.getElementById('clashMode').checked;
            document.getElementById('clashSettings').style.display = c ? 'block' : 'none';
            updateLink();
        }

        function updateLink() {
            let b = document.getElementById('subBaseUrl').value.trim();
            if (b.endsWith('/')) b = b.slice(0, -1);
            if (!b.startsWith('http')) b = 'https://' + b;
            
            const p = document.getElementById('proxyIp').value.trim();
            const h = HOST;
            const u = UUID;
            const c = document.getElementById('clashMode').checked;
            
            let rp = "/";
            if (p) rp = "/proxyip=" + p;
            
            const cl = b + "/sub?uuid=" + u + "&path=" + encodeURIComponent(rp);
            
            if (c) {
                let cv = document.getElementById('converterUrl').value.trim();
                if (cv.endsWith('/')) cv = cv.slice(0, -1);
                const cf = document.getElementById('configUrl').value.trim();
                document.getElementById('resultUrl').value = cv + "/sub?target=clash&url=" + encodeURIComponent(cl) + "&config=" + encodeURIComponent(cf) + "&emoji=true&list=false&tfo=false&scv=false&fdn=false&sort=false";
            } else {
                document.getElementById('resultUrl').value = cl;
            }
        }

        function copyId(id) {
            navigator.clipboard.writeText(document.getElementById(id).value).then(() => showToast("已复制!"));
        }

        function checkProxy() {
            const i = document.getElementById('proxyIp').value.trim();
            if (i) {
                navigator.clipboard.writeText(i).then(() => {
                    alert("ProxyIP 已复制!");
                    window.open("${PROXY_CHECK_URL}", "_blank");
                });
            } else {
                window.open("${PROXY_CHECK_URL}", "_blank");
            }
        }

        function showToast(m) {
            const t = document.getElementById('toast');
            t.innerText = m;
            t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 2000);
        }

        function logout() {
            document.cookie = "auth=;expires=Thu,01 Jan 1970 00:00:00 UTC;path=/;";
            location.reload();
        }

        window.onload = () => {
            updateLink();
        };
    </script>
</body>
</html>
  `;
}

// 登录页面
function loginPage() {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Worker Login</title><style>body{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;font-family:'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.glass-box{background:rgba(255,255,255,0.1);backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,0.2);padding:40px;border-radius:16px;box-shadow:0 8px 32px 0 rgba(31,38,135,0.37);text-align:center;width:320px}h2{margin-top:0;margin-bottom:20px;font-weight:600;letter-spacing:1px}input{width:100%;padding:14px;margin-bottom:20px;border-radius:8px;border:1px solid rgba(255,255,255,0.3);background:rgba(0,0,0,0.2);color:white;box-sizing:border-box;text-align:center;font-size:1rem;outline:none;transition:0.3s}input:focus{background:rgba(0,0,0,0.4);border-color:#a29bfe}button{width:100%;padding:12px;border-radius:8px;border:none;background:linear-gradient(90deg,#a29bfe,#6c5ce7);color:white;font-weight:bold;cursor:pointer;font-size:1rem;box-shadow:0 4px 15px rgba(0,0,0,0.2);transition:0.2s}button:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,0.3)}.social-links{margin-top:25px;display:flex;justify-content:center;gap:15px;border-top:1px solid rgba(255,255,255,0.1);padding-top:20px}.social-links a{color:#e2e8f0;text-decoration:none;font-size:0.9rem;padding:8px 16px;background:rgba(0,0,0,0.2);border-radius:20px;border:1px solid rgba(255,255,255,0.15);transition:0.2s;display:flex;align-items:center;gap:5px}.social-links a:hover{background:rgba(255,255,255,0.2);transform:translateY(-2px);border-color:#a29bfe}</style></head><body><div class="glass-box"><h2>🔒 音乐歌单</h2><input type="password" id="pwd" placeholder="请输入密码" autofocus onkeypress="if(event.keyCode===13)verify()"><button onclick="verify()">后台管理</button><div class="social-links"><a href="${TG_CHANNEL_URL}" target="_blank">📢 频道</a><a href="${TG_GROUP_URL}" target="_blank">✈️ 群组</a></div></div><script>function verify(){const p=document.getElementById('pwd').value;const d=new Date();d.setTime(d.getTime()+(7*24*60*60*1000));document.cookie="auth="+p+";expires="+d.toUTCString()+";path=/";location.reload()}</script></body></html>`;
}

export default {
  async fetch(r) { 
    const url = new URL(r.url);
    const host = url.hostname; 

    // =========================================================================
    // 🟢 1. 快速订阅接口 (/:SUB_PASSWORD)
    // =========================================================================
    if (SUB_PASSWORD && url.pathname === `/${SUB_PASSWORD}`) {
        const userAgent = (r.headers.get('User-Agent') || "").toLowerCase();
        const isClash = userAgent.includes('clash') || userAgent.includes('meta') || userAgent.includes('stash');
        const isFlagged = url.searchParams.has('flag');

        // Clash 回旋镖
        if (isClash && !isFlagged) {
            const requestProxyIp = url.searchParams.get('proxyip');
            let selfUrl = `https://${host}/${SUB_PASSWORD}?flag=true`;
            if (requestProxyIp) selfUrl += `&proxyip=${encodeURIComponent(requestProxyIp)}`;

            const converterUrl = `${DEFAULT_CONVERTER}/sub?target=clash&url=${encodeURIComponent(selfUrl)}&config=${encodeURIComponent(DEFAULT_CONFIG)}&emoji=true&list=false&tfo=false&scv=false&fdn=false&sort=false`;
            try {
                const subRes = await fetch(converterUrl);
                return new Response(subRes.body, { status: 200, headers: subRes.headers });
            } catch (err) {
                return new Response("Config conversion failed.", { status: 500 });
            }
        }

        // --- 核心抓取与替换逻辑 ---
        
        let upstream = DEFAULT_SUB_DOMAIN.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
        if (!upstream) upstream = host;
        
        let reqProxyIp = url.searchParams.get('proxyip');
        if (!reqProxyIp && DEFAULT_PROXY_IP && DEFAULT_PROXY_IP.trim() !== "") {
            reqProxyIp = DEFAULT_PROXY_IP;
        }

        let targetPath = "/";
        if (reqProxyIp && reqProxyIp.trim() !== "") {
            targetPath = `/proxyip=${reqProxyIp.trim()}`;
        }

        const params = new URLSearchParams();
        params.append("uuid", UUID);
        params.append("host", upstream);
        params.append("sni", upstream);
        params.append("path", targetPath); 
        params.append("type", "ws");
        params.append("encryption", "none");
        params.append("security", "tls");
        params.append("alpn", "h3");
        params.append("fp", "random");
        params.append("allowInsecure", "1");

        const upstreamUrl = `https://${upstream}/sub?${params.toString()}`;

        try {
            const response = await fetch(upstreamUrl, { 
                headers: { 
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" 
                } 
            });
            
            if (response.ok) {
                const text = await response.text();
                try {
                    let content = atob(text.trim());
                    content = content.replace(/path=[^&#]*/g, `path=${encodeURIComponent(targetPath)}`);
                    content = content.replace(/host=[^&]*/g, `host=${host}`);
                    content = content.replace(/sni=[^&]*/g, `sni=${host}`);
                    return new Response(btoa(content), { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
                } catch (e) {
                    return new Response(text, { status: 200 });
                }
            }
        } catch (e) {
            console.error(e);
        }
        
        // 降级本地
        const fallbackList = generateNodeList(host, UUID, reqProxyIp);
        return new Response(btoa(unescape(encodeURIComponent(fallbackList))), { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }

    // =========================================================================
    // 🟢 2. 常规订阅 /sub
    // =========================================================================
    if (url.pathname === '/sub') {
        const requestUUID = url.searchParams.get('uuid');
        if (requestUUID !== UUID) return new Response('Invalid UUID', { status: 403 });
        let pathParam = url.searchParams.get('path');
        let proxyIp = "";
        if (pathParam && pathParam.includes('/proxyip=')) proxyIp = pathParam.split('/proxyip=')[1];
        else if (pathParam === null) proxyIp = DEFAULT_PROXY_IP;
        const listText = generateNodeList(host, UUID, proxyIp);
        return new Response(btoa(unescape(encodeURIComponent(listText))), { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
    }

    // =========================================================================
    // 🟢 3. 带有音乐播放器的管理面板
    // =========================================================================
    if (r.headers.get('Upgrade') !== 'websocket') {
        if (WEB_PASSWORD && WEB_PASSWORD.trim().length > 0) {
            const cookie = r.headers.get('Cookie') || "";
            if (!cookie.includes(`auth=${WEB_PASSWORD}`)) return new Response(loginPage(), { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        }
        return new Response(generateMusicDashboard(host, UUID), { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
    
    let proxyIPConfig = null;
    if (url.pathname.includes('/proxyip=')) {
      try {
        const proxyParam = url.pathname.split('/proxyip=')[1].split('/')[0];
        const [address, port] = await 解析地址端口(proxyParam); 
        proxyIPConfig = { address, port: +port }; 
      } catch (e) {
         console.error('Failed to parse proxyip in fetch:', e.message);
      }
    }
    const { 0: c, 1: s } = new WebSocketPair(); s.accept(); 
    handle(s, proxyIPConfig); 
    return new Response(null, { status: 101, webSocket: c });
  }
};

const handle = (ws, proxyIPConfig) => {
  const pool = new Pool(); let sock, w, r, info, first = true, rxBytes = 0, stalls = 0, reconns = 0;
  let lastAct = Date.now(), conn = false, reading = false, writing = false; 
  const tmrs = {}, pend = [];
  let pendBytes = 0, score = 1.0, lastChk = Date.now(), lastRx = 0, succ = 0, fail = 0;
  let stats = { tot: 0, cnt: 0, big: 0, win: 0, ts: Date.now() }; 
  let mode = 'buffered', avgSz = 0, tputs = [];
  const updateMode = s => {
    stats.tot += s; stats.cnt++; if (s > 8192) stats.big++; avgSz = avgSz * 0.9 + s * 0.1; const now = Date.now();
    if (now - stats.ts > 1000) {
      const rate = stats.win; tputs.push(rate); if (tputs.length > 5) tputs.shift(); stats.win = s; stats.ts = now;
      const avg = tputs.reduce((a, b) => a + b, 0) / tputs.length;
      if (stats.cnt >= 20) {
        if (avg > 20971520 && avgSz > 16384) { if (mode !== 'direct') { mode = 'direct'; } }
        else if (avg < 10485760 || avgSz < 8192) { if (mode !== 'buffered') { mode = 'buffered'; pool.enableLarge(); } }
        else { if (mode !== 'adaptive') mode = 'adaptive'; }
      }} else { stats.win += s; }
  };
  const readLoop = async () => {
    if (reading) return; reading = true; let batch = [], bSz = 0, bTmr = null;
    const flush = () => {
      if (!bSz) return; const m = new Uint8Array(bSz); let p = 0;
      for (const c of batch) { m.set(c, p); p += c.length; }
      if (ws.readyState === 1) ws.send(m);
      batch = []; bSz = 0; if (bTmr) { clearTimeout(bTmr); bTmr = null; }
    };
    try {
      while (true) {
        if (pendBytes > MAX_PENDING) { await new Promise(res => setTimeout(res, 100)); continue; }
        const { done, value: v } = await r.read();
        if (v?.length) {
          rxBytes += v.length; lastAct = Date.now(); stalls = 0; updateMode(v.length); const now = Date.now();
          if (now - lastChk > 5000) {
            const el = now - lastChk, by = rxBytes - lastRx, tp = by / el;
            if (tp > 500) score = Math.min(1.0, score + 0.05);
            else if (tp < 50) score = Math.max(0.1, score - 0.05);
            lastChk = now; lastRx = rxBytes;
          }
          if (mode === 'buffered') {
            if (v.length < 32768) {
              batch.push(v); bSz += v.length;
              if (bSz >= 131072) flush();
              else if (!bTmr) bTmr = setTimeout(flush, avgSz > 16384 ? 5 : 20);
            } else { flush(); if (ws.readyState === 1) ws.send(v); }
          } else if (mode === 'adaptive') {
            if (v.length < 4096) {
              batch.push(v); bSz += v.length;
              if (bSz >= 32768) flush();
              else if (!bTmr) bTmr = setTimeout(flush, 15);
            } else { flush(); if (ws.readyState === 1) ws.send(v); }
          } else { flush(); if (ws.readyState === 1) ws.send(v); }
        } if (done) { flush(); reading = false; reconn(); break; }
      }} catch (e) { flush(); if (bTmr) clearTimeout(bTmr); reading = false; fail++; reconn(); }
  };
  const writeLoop = async () => {
    if (writing) return; writing = true;
    try {
      while(writing) { 
        if (!w) { await new Promise(res => setTimeout(res, 100)); continue; }
        if (pend.length === 0) { await new Promise(res => setTimeout(res, 20)); continue; }
        const b = pend.shift(); await w.write(b); pendBytes -= b.length; pool.free(b);
      }
    } catch (e) { writing = false; }
  };
  const attemptConnection = async () => {
    const connectionMethods = ['direct'];
    if (proxyIPConfig) { connectionMethods.push('proxy'); }
    let lastError;
    for (const method of connectionMethods) {
      try {
        const connectOpts = (method === 'direct')
          ? { hostname: info.host, port: info.port }
          : { hostname: proxyIPConfig.address, port: proxyIPConfig.port };
        const sock = connect(connectOpts); await sock.opened; return sock;
      } catch (e) { lastError = e; }
    }
    throw lastError || new Error('All connection methods failed.');
  };
  const establish = async () => { 
    try {
      sock = await attemptConnection(); w = sock.writable.getWriter(); r = sock.readable.getReader(); 
      conn = false; reconns = 0; score = Math.min(1.0, score + 0.15); succ++; lastAct = Date.now(); 
      readLoop(); writeLoop(); 
    } catch (e) { conn = false; fail++; score = Math.max(0.1, score - 0.2); reconn(); }
  };
  const reconn = async () => {
    if (!info || ws.readyState !== 1) { cleanup(); ws.close(1011, 'Invalid.'); return; }
    if (reconns >= MAX_RECONN) { cleanup(); ws.close(1011, 'Max reconnect.'); return; }
    if (score < 0.3 && reconns > 5 && Math.random() > 0.6) { cleanup(); ws.close(1011, 'Poor network.'); return; }
    if (conn) return; reconns++; let d = Math.min(50 * Math.pow(1.5, reconns - 1), 3000);
    d *= (1.5 - score * 0.5); d += (Math.random() - 0.5) * d * 0.2; d = Math.max(50, Math.floor(d));
    try {
      cleanSock();
      if (pendBytes > MAX_PENDING * 2) {
        while (pendBytes > MAX_PENDING && pend.length > 5) { const drop = pend.shift(); pendBytes -= drop.length; pool.free(drop); }
      }
      await new Promise(res => setTimeout(res, d)); conn = true;
      sock = await attemptConnection(); 
      w = sock.writable.getWriter(); r = sock.readable.getReader();
      conn = false; reconns = 0; score = Math.min(1.0, score + 0.15); succ++; stalls = 0; lastAct = Date.now(); 
      readLoop(); writeLoop(); 
    } catch (e) { 
      conn = false; fail++; score = Math.max(0.1, score - 0.2);
      if (reconns < MAX_RECONN && ws.readyState === 1) setTimeout(reconn, 500);
      else { cleanup(); ws.close(1011, 'Exhausted.'); }
    }
  };
  const startTmrs = () => {
    tmrs.ka = setInterval(async () => {
      if (!conn && w && Date.now() - lastAct > KEEPALIVE) { try { await w.write(new Uint8Array(0)); lastAct = Date.now(); } catch (e) { reconn(); }}
    }, KEEPALIVE / 3);
    tmrs.hc = setInterval(() => {
      if (!conn && stats.tot > 0 && Date.now() - lastAct > STALL_TO) { stalls++;
        if (stalls >= MAX_STALL) {
          if (reconns < MAX_RECONN) { stalls = 0; reconn(); }
          else { cleanup(); ws.close(1011, 'Stall.'); }
        }}}, STALL_TO / 2);
  };
  const cleanSock = () => { reading = false; writing = false; try { w?.releaseLock(); r?.releaseLock(); sock?.close(); } catch {} };
  const cleanup = () => {
    Object.values(tmrs).forEach(clearInterval); cleanSock();
    while (pend.length) pool.free(pend.shift());
    pendBytes = 0; stats = { tot: 0, cnt: 0, big: 0, win: 0, ts: Date.now() };
    mode = 'buffered'; avgSz = 0; tputs = []; pool.reset();
  };
  ws.addEventListener('message', async e => {
    try {
      if (first) {
        first = false; const b = new Uint8Array(e.data);
        if (buildUUID(b, 1).toLowerCase() !== UUID.toLowerCase()) throw new Error('Auth failed.');
        ws.send(new Uint8Array([0, 0])); 
        const { host, port, payload } = extractAddr(b); 
        info = { host, port }; conn = true; 
        if (payload.length) { const buf = pool.alloc(payload.length); buf.set(payload); pend.push(buf); pendBytes += buf.length; } 
        startTmrs(); establish(); 
      } else { 
        lastAct = Date.now(); if (pendBytes > MAX_PENDING * 2) return; 
        const buf = pool.alloc(e.data.byteLength); buf.set(new Uint8Array(e.data)); pend.push(buf); pendBytes += buf.length;
      }
    } catch (err) { cleanup(); ws.close(1006, 'Error.'); }
  }); 
  ws.addEventListener('close', cleanup); ws.addEventListener('error', cleanup);
};
