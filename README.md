# Network Port Scanner 🚀

A lightning-fast, concurrent network port scanner and subnet auditor with a real-time web dashboard. 

I built this project from scratch specifically to learn **Go (Golang)**. I wanted a hands-on way to understand Go's `goroutines`, concurrency models, and network socket programming. The frontend is built entirely in Vanilla JavaScript and HTML, utilizing HTTP chunked streaming to display real-time results without choking the browser.

## ✨ Features
* **Concurrent Scanning:** Uses Go worker pools to scan multiple ports simultaneously.
* **Subnet Auditing:** Automatically maps active devices across a local /24 subnet.
* **Real-Time Web UI:** Streams data chunks directly to the browser for a live terminal feel.
* **Throttled for Stability:** Fine-tuned to 50 concurrent workers with 400ms timeouts to prevent local network hardware (like home routers) from dropping packets due to SYN flood protections.

## 🛠️ Tech Stack
* **Backend:** Go (`net`, `net/http`, `sync`)
* **Frontend:** Vanilla HTML, CSS, JavaScript (`TextDecoder` streams)

## 🚀 How to Run It

### Option 1: The Easy Way (Windows .exe)
If you are on Windows and just want to use the scanner without installing anything:
1. Go to the [Releases](../../releases) tab on the right side of this page.
2. Download the latest `PortScanner.exe` file.
3. Double-click the `.exe` (a console window will open to host the backend).
4. Open your web browser and navigate to `http://localhost:8080`.

### Option 2: Run from Source (For Developers)
If you want to run the code yourself or compile it for Linux/macOS, you will need [Go installed](https://go.dev/doc/install) on your machine.

1. Clone this repository:
   ```bash
   git clone [https://github.com/ayeshakhan2004/Port_Scanner.git](https://github.com/ayeshakhan2004/Port_Scanner.git)
   cd YOUR_REPO_NAME
   ```

Run the code directly:

   ```bash
    
   go run main.go
    
   ```
    
Or compile it into an executable:

  ```bash
    
  go build -o PortScanner.exe main.go
    
  ```
    
Open your web browser to http://localhost:8080.

## 🧠 Biggest Lesson Learned: The "Accidental DDoS"
During development, I initially didn't throttle the goroutines. The Go backend fired off thousands of TCP connection requests (SYN packets) instantly. It was so fast that my local router's Intrusion Prevention System (IPS) flagged my PC as a threat and silently dropped all the packets! I had to learn how to properly balance a worker pool to find the sweet spot between maximum speed and network stability.

## ⚠️ Disclaimer
For educational purposes only. This tool was built to learn about network protocols and Go concurrency. Only scan networks and devices that you own or have explicit, written permission to test.
