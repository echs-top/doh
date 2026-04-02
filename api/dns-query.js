const fs = require('fs');
const path = require('path');
const dnsPacket = require('dns-packet');

let hostsMap = new Map();
let isLoaded = false;

// 加载 hosts 文件的逻辑（保持不变）
function loadHosts() {
    if (isLoaded) return;
    try {
        const hostsPath = path.join(process.cwd(), 'hosts.txt');
        const data = fs.readFileSync(hostsPath, 'utf8');
        const lines = data.split('\n');
        
        lines.forEach(line => {
            const cleanLine = line.split('#')[0].trim();
            if (!cleanLine) return;
            const parts = cleanLine.split(/\s+/);
            if (parts.length >= 2) {
                const ip = parts[0];
                for (let i = 1; i < parts.length; i++) {
                    hostsMap.set(parts[i].toLowerCase(), ip); 
                }
            }
        });
        isLoaded = true;
    } catch (error) {
        console.error('无法读取 hosts.txt:', error);
    }
}

// 【关键配置】禁用 Vercel 默认的 body 解析器，这样我们可以直接读取客户端发来的 POST 二进制流
module.exports.config = {
    api: {
        bodyParser: false,
    },
};

module.exports = async (req, res) => {
    // 允许跨域，并设置标准 DoH 的 Content-Type
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/dns-message');

    loadHosts();

    let dnsBuffer;

    try {
        // 1. 获取客户端发来的 DNS 二进制数据
        if (req.method === 'GET') {
            // 标准 DoH GET 请求会将包进行 Base64Url 编码并放在 dns 参数中
            const dnsQuery = req.query.dns;
            if (!dnsQuery) {
                return res.status(400).send('Bad Request: Missing dns parameter');
            }
            // Base64Url 解码
            const base64 = dnsQuery.replace(/-/g, '+').replace(/_/g, '/');
            const padding = '='.repeat((4 - base64.length % 4) % 4);
            dnsBuffer = Buffer.from(base64 + padding, 'base64');
            
        } else if (req.method === 'POST') {
            // 标准 DoH POST 请求直接发送二进制数据体
            dnsBuffer = await new Promise((resolve, reject) => {
                const chunks = [];
                req.on('data', chunk => chunks.push(chunk));
                req.on('end', () => resolve(Buffer.concat(chunks)));
                req.on('error', reject);
            });
        } else {
            return res.status(405).send('Method Not Allowed');
        }

        // 2. 解析 DNS 查询包
        const packet = dnsPacket.decode(dnsBuffer);
        const question = packet.questions[0];

        if (!question) {
            return res.status(400).send('Bad Request: No question found');
        }

        const searchName = question.name.toLowerCase();
        const ip = hostsMap.get(searchName);

        // 3. 构造 DNS 响应包
        const responsePacket = {
            type: 'response',
            id: packet.id,
            questions: packet.questions,
            answers: []
        };

        if (ip) {
            // 命中 hosts.txt：判断是 IPv4(A) 还是 IPv6(AAAA)
            const isIPv6 = ip.includes(':');
            const recordType = isIPv6 ? 'AAAA' : 'A';
            
            // 客户端请求什么类型，我们就看看是不是匹配
            if (question.type === recordType || question.type === 'ANY') {
                responsePacket.answers.push({
                    type: recordType,
                    class: 'IN',
                    name: question.name,
                    ttl: 600, // 缓存时间，单位：秒
                    data: ip
                });
            }
            // 0x8180 = 标准响应 + 递归期望 + 递归可用 + 状态码 NOERROR (0)
            responsePacket.flags = 0x8180; 
        } else {
            // 没有命中 hosts.txt，直接返回 NXDOMAIN (域名不存在)
            // 0x8183 = 标准响应 + 递归期望 + 递归可用 + 状态码 NXDOMAIN (3)
            responsePacket.flags = 0x8183;
        }

        // 4. 将响应包重新编码为二进制并发送回客户端
        const responseBuffer = dnsPacket.encode(responsePacket);
        res.status(200).send(responseBuffer);

    } catch (err) {
        console.error('DNS Processing Error:', err);
        res.status(400).send('Bad Request: Invalid DNS payload');
    }
};
