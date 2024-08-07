import React, { useState } from 'react';
import axios from 'axios';

const App = () => {
  const [input, setInput] = useState('');
  const [fileHash, setFileHash] = useState('');
  const [url, setUrl] = useState('');
  const [ip, setIp] = useState('');
  const [domain, setDomain] = useState('');
  const [gptResult, setGptResult] = useState('');
  const [vtScanResult, setVtScanResult] = useState('');
  const [vtScanSummary, setVtScanSummary] = useState('');
  const [vtDnsResult, setVtDnsResult] = useState('');
  const [vtDnsSummary, setVtDnsSummary] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadResult, setUploadResult] = useState('');
  const [finalSummary, setFinalSummary] = useState('');

  const handleGptRequest = async () => {
    try {
      const response = await axios.post('http://localhost:5000/gpt', { text: input });
      setGptResult(response.data.result);
    } catch (error) {
      console.error('Error fetching GPT-4 result:', error);
    }
  };

  const handleVtScanRequest = async () => {
    try {
      const response = await axios.post('http://localhost:5000/vt/scan', { fileHash, url, ip });
      setVtScanResult(JSON.stringify(response.data.result, null, 2));
      setVtScanSummary(response.data.summary);
    } catch (error) {
      console.error('Error fetching VirusTotal scan result:', error);
    }
  };

  const handleVtDnsRequest = async () => {
    try {
      const response = await axios.post('http://localhost:5000/vt/dns', { domain });
      setVtDnsResult(JSON.stringify(response.data.result, null, 2));
      setVtDnsSummary(response.data.summary);
    } catch (error) {
      console.error('Error fetching VirusTotal DNS result:', error);
    }
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    setSelectedFile(file);
  };

  const uploadFile = async () => {
    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await axios.post('http://localhost:5000/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      setUploadResult(JSON.stringify(response.data, null, 2));
    } catch (error) {
      console.error('Error uploading file:', error);
    }
  };

  const handleFinalSummaryRequest = async () => {
    try {
      const response = await axios.post('http://localhost:5000/complete_summary', {
        file_metadata_summary: uploadResult,
        vt_scan_result: vtScanSummary,
        vt_dns_result: vtDnsSummary,
      });
      setFinalSummary(response.data.summary);
    } catch (error) {
      console.error('Error fetching final summary:', error);
    }
  };

  return (
    <div>
      <h1>React Integration with GPT-4 and VirusTotal</h1>

      <h2>GPT-4 Request</h2>
      <input
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Enter text"
      />
      <button onClick={handleGptRequest}>Get GPT-4 Result</button>
      <div>
        <h3>GPT-4 Result:</h3>
        <p>{gptResult}</p>
      </div>

      <h2>VirusTotal Scan</h2>
      <input
        type="text"
        value={fileHash}
        onChange={(e) => setFileHash(e.target.value)}
        placeholder="File Hash"
      />
      <input
        type="text"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="URL"
      />
      <input
        type="text"
        value={ip}
        onChange={(e) => setIp(e.target.value)}
        placeholder="IP Address"
      />
      <button onClick={handleVtScanRequest}>Get VirusTotal Scan Result</button>
      <div>
        <h3>VirusTotal Scan Result:</h3>
        <pre>{vtScanResult}</pre>
        <h3>VirusTotal Scan Summary:</h3>
        <p>{vtScanSummary}</p>
      </div>

      <h2>VirusTotal DNS</h2>
      <input
        type="text"
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        placeholder="Domain"
      />
      <button onClick={handleVtDnsRequest}>Get VirusTotal DNS Result</button>
      <div>
        <h3>VirusTotal DNS Result:</h3>
        <pre>{vtDnsResult}</pre>
        <h3>VirusTotal DNS Summary:</h3>
        <p>{vtDnsSummary}</p>
      </div>

      <h2>File Upload</h2>
      <input type="file" onChange={handleFileUpload} />
      <button onClick={uploadFile}>Upload File</button>
      <div>
        <h3>Upload Result:</h3>
        <pre>{uploadResult}</pre>
      </div>

      <h2>Final Summary</h2>
      <button onClick={handleFinalSummaryRequest}>Get Final Summary</button>
      <div>
        <h3>Final Summary:</h3>
        <pre>{finalSummary}</pre>
      </div>
    </div>
  );
};

export default App;
