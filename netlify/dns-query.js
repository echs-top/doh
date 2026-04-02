const fs = require('fs');
const path = require('path');
const dnsPacket = require('dns-packet');

let hostsMap = new Map();
let isLoaded = false;

// 加载 hosts 文件的逻辑与之前完全一致
function loadHosts() {
    if (isLoaded) return;
    try {
        // Netlify 环境中，process.cwd() 同样指向项目根目录
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
                    if (!hostsMap.has(domain)) {
                        hostsMap.set(domain, { A: [], AAAA: [] });
                    }
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

// Netlify 规范的入口函数：使用 event 和 context
exports.handler = async function(event, context) {
    loadHosts();

    let dnsBuffer;

    try {
        // 1. 获取客户端发来的 DNS 二进制数据
        if (event.httpMethod === 'GET') {
            const dnsQuery = event.queryStringParameters.dns;
            if (!dnsQuery) return { statusCode: 400, body: 'Bad Request: Missing dns parameter' };
            const base64 = dnsQuery.replace(/-/g, '+').replace(/_/g, '/');
            const padding = '='.repeat((4 - base64.length % 4) % 4);
            dnsBuffer = Buffer.from(base64 + padding, 'base64');
            
        } else if (event.httpMethod === 'POST') {
            // Netlify 会自动将 POST 请求的二进制 body 转为 base64，我们需要解码
            if (event.isBase64Encoded) {
                dnsBuffer = Buffer.from(event.body, 'base64');
            } else {
                dnsBuffer = Buffer.from(event.body);
            }
        } else {
            return { statusCode: 405, body: 'Method Not Allowed' };
        }

        // 2. 解析查询包
        const packet = dnsPacket.decode(dnsBuffer);
        const question = packet.questions[0];

        if (!question) return { statusCode: 400, body: 'Bad Request: No question found' };

        const searchName = question.name.toLowerCase();
        const record = hostsMap.get(searchName);

        // 3. 构建响应包
        const responsePacket = {
            type: 'response',
            id: packet.id,
            questions: packet.questions,
            answers: []
        };

        if (record) {
            responsePacket.flags = 0x8180; // NOERROR
            if (question.type === 'A' || question.type === 'ANY') {
                record.A.forEach(ip => {
                    responsePacket.answers.push({ type: 'A', class: 'IN', name: question.name, ttl: 600, data: ip });
                });
            }
            if (question.type === 'AAAA' || question.type === 'ANY') {
                record.AAAA.forEach(ip => {
                    responsePacket.answers.push({ type: 'AAAA', class: 'IN', name: question.name, ttl: 600, data: ip });
                });
            }
        } else {
            responsePacket.flags = 0x8183; // NXDOMAIN
        }

        // 4. 将响应包转为二进制
        const responseBuffer = dnsPacket.encode(responsePacket);

        // 5. 【Netlify 特有】必须将二进制 Buffer 转为 Base64 字符串返回，并声明 isBase64Encoded: true
        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Content-Type': 'application/dns-message'
            },
            body: responseBuffer.toString('base64'),
            isBase64Encoded: true
        };

    } catch (err) {
        console.error('DNS Processing Error:', err);
        return { statusCode: 400, body: 'Bad Request: Invalid DNS payload' };
    }
};
