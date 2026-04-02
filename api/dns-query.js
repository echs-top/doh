const fs = require('fs');
const path = require('path');

// 全局变量，在 Vercel 的函数实例生命周期内缓存 hosts 记录
let hostsMap = new Map();
let isLoaded = false;

// 读取并解析 hosts.txt 的函数
function loadHosts() {
    if (isLoaded) return;
    try {
        // 在 Vercel 中，process.cwd() 指向项目根目录
        const hostsPath = path.join(process.cwd(), 'hosts.txt');
        const data = fs.readFileSync(hostsPath, 'utf8');
        const lines = data.split('\n');
        
        lines.forEach(line => {
            // 忽略注释 (#后面的内容) 和首尾空格
            const cleanLine = line.split('#')[0].trim();
            if (!cleanLine) return; // 跳过空行
            
            // 按空白字符（空格或制表符）分割
            const parts = cleanLine.split(/\s+/);
            if (parts.length >= 2) {
                const ip = parts[0];
                // 支持同一行定义多个域名
                for (let i = 1; i < parts.length; i++) {
                    // 统一转换为小写，保证域名查询不区分大小写
                    hostsMap.set(parts[i].toLowerCase(), ip); 
                }
            }
        });
        isLoaded = true;
        console.log('Hosts 文件加载成功，共加载条目:', hostsMap.size);
    } catch (error) {
        console.error('无法读取 hosts.txt:', error);
    }
}

module.exports = (req, res) => {
    // 1. 设置跨域头，允许任何客户端调用
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/dns-json');

    // 2. 加载 hosts 数据（如果已加载则会直接跳过）
    loadHosts();

    // 3. 解析请求参数
    // DoH JSON API 通常通过 GET 请求的查询参数传递 name (域名) 和 type (记录类型)
    const { name, type = '1' } = req.query;

    if (!name) {
        return res.status(400).json({ error: 'Missing domain name in query' });
    }

    // 格式化查询的域名（转小写，并移除结尾可能带有的根点 "."）
    const searchName = name.toLowerCase().replace(/\.$/, ''); 
    const ip = hostsMap.get(searchName);

    // 构建 Question 部分
    const question = [{ name: searchName, type: parseInt(type) || 1 }];

    // 4. 根据查询结果返回响应
    if (ip) {
        // 简单判断是 IPv4 还是 IPv6，以便返回正确的 Type 标识 (A: 1, AAAA: 28)
        const recordType = ip.includes(':') ? 28 : 1;
        
        // 状态码 0 代表 NOERROR (成功)
        return res.status(200).json({
            Status: 0, 
            TC: false,
            RD: true,
            RA: false,
            AD: false,
            CD: false,
            Question: question,
            Answer: [
                {
                    name: searchName,
                    type: recordType,
                    TTL: 600, // 缓存时间（秒），可自定义
                    data: ip
                }
            ]
        });
    } else {
        // 状态码 3 代表 NXDOMAIN (域名不存在)
        return res.status(200).json({
            Status: 3, 
            TC: false,
            RD: true,
            RA: false,
            AD: false,
            CD: false,
            Question: question
        });
    }
};
