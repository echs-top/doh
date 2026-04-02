const fs = require('fs');
const path = require('path');
const dnsPacket = require('dns-packet');

let hostsMap = new Map();
let isLoaded = false;

// 重新设计的读取逻辑：支持一个域名绑定多个 IP（双栈支持）
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
                const isIPv6 = ip.includes(':');
                
                for (let i = 1; i < parts.length; i++) {
                    const domain = parts[i].toLowerCase();
                    
                    // 如果字典里没有这个域名，先初始化一个空对象
                    if (!hostsMap.has(domain)) {
                        hostsMap.set(domain, { A: [], AAAA: [] });
                    }
                    
                    // 将 IP 放入对应的数组中，并去重
                    const record = hostsMap.get(domain);
                    if (isIPv6) {
                        if (!record.AAAA.includes(ip)) record.AAAA.push(ip);
                    } else {
                        if (!record.A.includes(ip)) record.A.push(ip);
                    }
                }
            }
        });
        isLoaded = true;
    } catch (error) {
        console.error('无法读取 hosts.txt:', error);
    }
}

module.exports.config = {
    api: {
        bodyParser: false,
    },
};

module.exports = async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/dns-message');

    loadHosts();

    let dnsBuffer;

    try {
        if (req.method === 'GET') {
            const dnsQuery = req.query.dns;
            if (!dnsQuery) return res.status(400).send('Bad Request: Missing dns parameter');
            const base64 = dnsQuery.replace(/-/g, '+').replace(/_/g, '/');
            const padding = '='.repeat((4 - base64.length % 4) % 4);
            dnsBuffer = Buffer.from(base64 + padding, 'base64');
        } else if (req.method === 'POST') {
            dnsBuffer = await new Promise((resolve, reject) => {
                const chunks = [];
                req.on('data', chunk => chunks.push(chunk));
                req.on('end', () => resolve(Buffer.concat(chunks)));
                req.on('error', reject);
            });
        } else {
            return res.status(405).send('Method Not Allowed');
        }

        const packet = dnsPacket.decode(dnsBuffer);
        const question = packet.questions[0];

        if (!question) return res.status(400).send('Bad Request: No question found');

        const searchName = question.name.toLowerCase();
        // 获取该域名下的所有记录（包含 A 和 AAAA 数组）
        const record = hostsMap.get(searchName);

        const responsePacket = {
            type: 'response',
            id: packet.id,
            questions: packet.questions,
            answers: []
        };

        if (record) {
            // 命中记录：状态码 NOERROR (0)
            responsePacket.flags = 0x8180; 
            
            // 如果客户端请求 A 记录或 ANY 记录，且我们有 IPv4 数据，则全部返回
            if (question.type === 'A' || question.type === 'ANY') {
                record.A.forEach(ip => {
                    responsePacket.answers.push({ type: 'A', class: 'IN', name: question.name, ttl: 600, data: ip });
                });
            }
            // 如果客户端请求 AAAA 记录或 ANY 记录，且我们有 IPv6 数据，则全部返回
            if (question.type === 'AAAA' || question.type === 'ANY') {
                record.AAAA.forEach(ip => {
                    responsePacket.answers.push({ type: 'AAAA', class: 'IN', name: question.name, ttl: 600, data: ip });
                });
            }
        } else {
            // 未命中，返回 NXDOMAIN (3)
            responsePacket.flags = 0x8183;
        }

        const responseBuffer = dnsPacket.encode(responsePacket);
        res.status(200).send(responseBuffer);

    } catch (err) {
        console.error('DNS Processing Error:', err);
        res.status(400).send('Bad Request: Invalid DNS payload');
    }
};
