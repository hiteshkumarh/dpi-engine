const express = require('express');
const multer = require('multer');
const cors = require('cors');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Create uploads folder if not exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Multer config
const upload = multer({
    dest: uploadDir
});

// Health check
app.get('/', (req, res) => {
    res.send('DPI Backend Running');
});

// 🔥 MAIN ANALYZE ENDPOINT
app.post('/api/analyze', upload.single('pcap'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    const inputPath = req.file.path;
    const outputPath = path.join(uploadDir, `output_${Date.now()}.pcap`);
    const dpiPath = path.join(__dirname, '..', 'packet_analyzer_py', 'main.py');

    // Parse custom rules string from frontend
    const rulesStr = req.body.rules || '';
    const extraArgs = rulesStr.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
    const cleanArgs = extraArgs.map(arg => arg.replace(/^"|"$/g, ''));

    const args = ['-X', 'utf8', dpiPath, inputPath, outputPath, ...cleanArgs];

    const { spawn } = require('child_process');
    const child = spawn('python', args);

    let stdoutData = '';
    let stderrData = '';

    child.stdout.on('data', (data) => {
        stdoutData += data.toString();
    });

    child.stderr.on('data', (data) => {
        stderrData += data.toString();
    });

    child.on('close', (code) => {
        if (code !== 0 && code !== null) {
            console.error(`Process exited with code ${code}: ${stderrData}`);
            return res.status(500).json({ error: stderrData || 'Unknown execution error' });
        }

        const result = parseDPIOutput(stdoutData);
        res.json({ ...result, rawOutput: alignAsciiArt(stdoutData) });
    });
});

// Parse stdout into structured JSON
function parseDPIOutput(output) {
    const totalPacketsMatch = output.match(/Total Packets:\s+(\d+)/);
    const forwardedMatch = output.match(/Forwarded:\s+(\d+)/);
    const droppedMatch = output.match(/Dropped:\s+(\d+)/);

    return {
        totalPackets: totalPacketsMatch ? Number(totalPacketsMatch[1]) : 0,
        forwarded: forwardedMatch ? Number(forwardedMatch[1]) : 0,
        dropped: droppedMatch ? Number(droppedMatch[1]) : 0
    };
}

// Ensure ASCII box borders align perfectly
function alignAsciiArt(text) {
    const lines = text.split(/\r?\n/);
    let borderLen = 0;
    for (const l of lines) {
        if (l.startsWith('╔') || l.startsWith('╠') || l.startsWith('╚')) {
            borderLen = Math.max(borderLen, Array.from(l).length);
        }
    }
    return lines.map(line => {
        const m = line.match(/^(║)(.*)(║)\s*$/);
        if (m && borderLen > 0) {
            const inner = m[2];
            const stripped = inner.replace(/\s+$/, '');
            const pad = borderLen - 2 - Array.from(stripped).length;
            return '║' + stripped + (pad > 0 ? ' '.repeat(pad) : '') + '║';
        }
        return line;
    }).join('\n');
}

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});