package main

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func grabServiceInfo(conn net.Conn, port int) string {
	conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if port == 80 || port == 443 || port == 8080 {
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: local\r\n\r\n")
	} else if port == 53 {
		conn.Write([]byte("\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"))
	}

	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)

	if n == 0 {
		if port == 53 {
			return "DNS Service Detected (Active)"
		}
		return "Unknown Service"
	}

	rawResponse := string(buf[:n])
	cleanStr := strings.ReplaceAll(rawResponse, "\r", "")
	lines := strings.Split(cleanStr, "\n")
	firstLine := strings.TrimSpace(lines[0])

	if len(firstLine) > 60 {
		firstLine = firstLine[:57] + "..."
	}

	if strings.Contains(rawResponse, "SSH") {
		return "SSH: " + firstLine
	}
	if strings.Contains(rawResponse, "HTTP") || strings.Contains(strings.ToLower(rawResponse), "html") {
		return "Web Server: " + firstLine
	}
	return "Banner: " + firstLine
}

type AuditJob struct {
	IP   string
	Port int
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlTemplate))
	})

	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, _ := w.(http.Flusher)

		target := r.URL.Query().Get("ip")
		s, _ := strconv.Atoi(r.URL.Query().Get("start"))
		e, _ := strconv.Atoi(r.URL.Query().Get("end"))

		fmt.Fprintf(w, "[*] Starting Deep Scan on %s (Throttled Worker Pool)...\n", target)
		if flusher != nil {
			flusher.Flush()
		}

		jobs := make(chan int, e-s+1)
		resultChan := make(chan string, 100)
		writerDone := make(chan bool)

		go func() {
			for msg := range resultChan {
				fmt.Fprint(w, msg)
				if flusher != nil {
					flusher.Flush()
				}
			}
			writerDone <- true
		}()

		var wg sync.WaitGroup
		// THROTTLED CONCURRENCY: Lowered from 100 to 10 to stop local routers from dropping packets
		workerCount := 10
		if e-s < workerCount {
			workerCount = e - s + 1
		}

		for wIndex := 0; wIndex < workerCount; wIndex++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for port := range jobs {
					address := fmt.Sprintf("%s:%d", target, port)
					conn, err := net.DialTimeout("tcp", address, 1500*time.Millisecond)
					if err == nil {
						info := grabServiceInfo(conn, port)
						resultChan <- fmt.Sprintf("[+] Found %s Port %d: %s\n", target, port, info)
						conn.Close()
					}
				}
			}()
		}

		for p := s; p <= e; p++ {
			jobs <- p
		}
		close(jobs)

		wg.Wait()
		close(resultChan)
		<-writerDone

		fmt.Fprintf(w, "\nStatus: Scan Complete\n")
		if flusher != nil {
			flusher.Flush()
		}
	})

	http.HandleFunc("/audit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		flusher, _ := w.(http.Flusher)

		subnet := r.URL.Query().Get("subnet")
		fmt.Fprintf(w, "[*] Auditing Subnet %s.0/24...\n", subnet)
		if flusher != nil {
			flusher.Flush()
		}

		commonPorts := []int{21, 22, 23, 53, 80, 443, 445, 8080}
		jobs := make(chan AuditJob, 255*len(commonPorts))
		resultChan := make(chan string, 100)
		writerDone := make(chan bool)

		go func() {
			for msg := range resultChan {
				fmt.Fprint(w, msg)
				if flusher != nil {
					flusher.Flush()
				}
			}
			writerDone <- true
		}()

		var wg sync.WaitGroup
		// THROTTLED CONCURRENCY: Lowered from 100 to 10 to prevent network hardware from blocking requests
		for wIndex := 0; wIndex < 10; wIndex++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobs {
					address := fmt.Sprintf("%s:%d", j.IP, j.Port)
					conn, err := net.DialTimeout("tcp", address, 1500*time.Millisecond)
					if err == nil {
						info := grabServiceInfo(conn, j.Port)
						resultChan <- fmt.Sprintf("[Device: %s] Port %d: %s\n", j.IP, j.Port, info)
						conn.Close()
					}
				}
			}()
		}

		for i := 1; i < 255; i++ {
			targetIP := fmt.Sprintf("%s.%d", subnet, i)
			for _, p := range commonPorts {
				jobs <- AuditJob{IP: targetIP, Port: p}
			}
		}
		close(jobs)

		wg.Wait()
		close(resultChan)
		<-writerDone

		fmt.Fprintf(w, "\nStatus: Audit Complete\n")

		flusher.Flush()

	})

	fmt.Println("======================================")
	fmt.Println(" Port Scanner")
	fmt.Println(" Open your browser to: http://localhost:8080")
	fmt.Println("======================================")

	http.ListenAndServe(":8080", nil)
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Scanner</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --panel-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-red: #ef4444;
            --border-color: #334155;
            --terminal-bg: #020617;
            --terminal-text: #38bdf8;
        }

        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            background: var(--bg-color); 
            color: var(--text-main); 
            margin: 0; 
            padding: 40px 20px; 
            display: flex; 
            justify-content: center; 
        }

        .dashboard { 
            background: var(--panel-bg); 
            padding: 30px; 
            border-radius: 16px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.5); 
            width: 100%; 
            max-width: 800px; 
            border: 1px solid var(--border-color);
        }

        header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
        }

        h1 { margin: 0; font-size: 28px; color: var(--text-main); font-weight: 700; }
        p.subtitle { margin: 5px 0 0; color: var(--text-muted); font-size: 14px; }

        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 25px;
        }

        .full-width { grid-column: span 2; }

        .input-group { display: flex; flex-direction: column; gap: 8px; }
        
        label { font-size: 13px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        
        input { 
            padding: 12px 15px; 
            background: rgba(15, 23, 42, 0.5); 
            border: 1px solid var(--border-color); 
            color: white; 
            border-radius: 8px; 
            font-size: 15px; 
            outline: none; 
            transition: all 0.3s ease;
        }
        
        input:focus { border-color: var(--accent-blue); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2); }

        .actions { display: flex; gap: 15px; margin-bottom: 25px; }

        button { 
            flex: 1; 
            padding: 14px; 
            font-size: 15px; 
            font-weight: 600; 
            border: none; 
            border-radius: 8px; 
            cursor: pointer; 
            transition: all 0.2s ease; 
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
        }

        button.primary { background: var(--accent-blue); color: #fff; }
        button.primary:hover { background: #2563eb; transform: translateY(-2px); }

        button.secondary { background: var(--accent-purple); color: #fff; }
        button.secondary:hover { background: #7c3aed; transform: translateY(-2px); }

        button.danger { background: transparent; border: 1px solid var(--accent-red); color: var(--accent-red); flex: 0.3; }
        button.danger:hover { background: var(--accent-red); color: white; }

        .terminal-container {
            background: var(--terminal-bg);
            border-radius: 10px;
            border: 1px solid var(--border-color);
            overflow: hidden;
        }

        .terminal-header {
            background: #1e293b;
            padding: 10px 15px;
            display: flex;
            align-items: center;
            gap: 8px;
            border-bottom: 1px solid var(--border-color);
        }

        .dot { width: 12px; height: 12px; border-radius: 50%; }
        .dot.red { background: #ff5f56; }
        .dot.yellow { background: #ffbd2e; }
        .dot.green { background: #27c93f; }
        .term-title { margin-left: auto; margin-right: auto; color: var(--text-muted); font-size: 12px; font-weight: 600; padding-right: 45px;}

        pre { 
            margin: 0; 
            padding: 20px; 
            height: 350px; 
            overflow-y: auto; 
            color: var(--terminal-text); 
            font-family: 'Fira Code', 'Courier New', monospace; 
            font-size: 14px;
            line-height: 1.5;
            white-space: pre-wrap; 
        }

        pre::-webkit-scrollbar { width: 8px; }
        pre::-webkit-scrollbar-track { background: var(--terminal-bg); }
        pre::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
        pre::-webkit-scrollbar-thumb:hover { background: #64748b; }
    </style>
</head>
<body>
    <div class="dashboard">
        <header>
            <h1>Port Scanner</h1>
            <p class="subtitle">Network Security & Port Analysis Dashboard</p>
        </header>
        
        <div class="form-grid">
            <div class="input-group full-width">
                <label>Target (IP or Subnet)</label>
                <input id="target" type="text" placeholder="192.168.1.1" value="192.168.1.1" />
            </div>
            <div class="input-group">
                <label>Start Port</label>
                <input id="start" type="number" value="1" />
            </div>
            <div class="input-group">
                <label>End Port</label>
                <input id="end" type="number" value="1024" />
            </div>
        </div>

        <div class="actions">
            <button class="primary" onclick="runScan()">🔍 Deep Scan</button>
            <button class="secondary" onclick="runAudit()">📡 Subnet Audit</button>
            <button class="danger" onclick="clearTerminal()">🗑️</button>
        </div>

        <div class="terminal-container">
            <div class="terminal-header">
                <span class="dot red"></span>
                <span class="dot yellow"></span>
                <span class="dot green"></span>
                <span class="term-title">bash - session</span>
            </div>
            <pre id="output">System Ready... Select an action to begin.</pre>
        </div>
    </div>

    <script>
        let isScanning = false;

        async function streamResults(url, initMessage) {
            let out = document.getElementById('output');
            out.textContent = initMessage + "\n";
            isScanning = true;
            
            try {
                let response = await fetch(url);
                let reader = response.body.getReader();
                let decoder = new TextDecoder("utf-8");
                
                while(true) {
                    let {done, value} = await reader.read();
                    if(done) break;
                    let chunk = decoder.decode(value, {stream: true});
                    out.textContent += chunk;
                    out.scrollTop = out.scrollHeight;

                }
            } catch (err) {
                out.textContent += "\n[!] Connection lost to backend scanner engine.";
            } finally {
                isScanning = false;
            }
        }

        function runScan() {
            if (isScanning) return;
            let target = document.getElementById('target').value.trim();
            let s = document.getElementById('start').value;
            let e = document.getElementById('end').value;
            streamResults('/scan?ip=' + target + '&start=' + s + '&end=' + e, "[*] Initializing Deep Scan on " + target + "...");
        }

        function runAudit() {
            if (isScanning) return;
            let rawTarget = document.getElementById('target').value.trim();
            
            if (rawTarget.includes("/")) {
                rawTarget = rawTarget.split("/")[0];
            }
            
            let parts = rawTarget.split('.');
            let subnet = "192.168.1";
            if (parts.length >= 3) {
                subnet = parts[0] + "." + parts[1] + "." + parts[2];
            }
            
            streamResults('/audit?subnet=' + subnet, "[*] Initializing Audit on subnet " + subnet + ".0/24...");
        }

        function clearTerminal() {
            document.getElementById('output').textContent = "System Ready... Select an action to begin.";
        }
    </script>
</body>
</html>
`
